use crate::identity::{Claim, Identity, PublicIdentity, ServerKey};
use ed25519_dalek::VerifyingKey;
use snow::{Builder, TransportState};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Noise protocol hard limit: 65535 bytes per message
const MAX_NOISE_PLAINTEXT: usize = 65535;

// Noise ChaChaPoly adds 16 bytes MAC tag to each message
const NOISE_TAG_LEN: usize = 16;

// Maximum Noise ciphertext size (plaintext + tag)
const MAX_NOISE_CIPHERTEXT: usize = MAX_NOISE_PLAINTEXT + NOISE_TAG_LEN;

// Handshake-only limit: VDF claims shouldn't exceed 64KB
const MAX_HANDSHAKE_MESSAGE: usize = 65536;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

/// Client-side Noise_XX handshake. Returns transport state and server's static key.
pub async fn noise_xx_client<S>(
    stream: &mut S,
    identity: &Identity,
    claim: &Claim,
) -> io::Result<(TransportState, [u8; 32])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let pattern = NOISE_PATTERN.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Invalid Noise pattern: {}", e))
    })?;

    // Convert Ed25519 private key to Curve25519 scalar for Noise
    let curve25519_scalar = identity.signing_key().to_scalar_bytes();

    let mut noise = Builder::new(pattern)
        .local_private_key(&curve25519_scalar)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Noise local_private_key failed: {}", e)))?
        .build_initiator()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Noise init failed: {}", e)))?;

    let mut buf = vec![0u8; MAX_HANDSHAKE_MESSAGE];

    // -> e
    let len = noise.write_message(&[], &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise write_message failed: {}", e))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    // <- e, ee, s, es
    let len = stream.read_u16().await? as usize;
    if len > MAX_HANDSHAKE_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Noise message too large"));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    noise.read_message(&msg, &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise read_message failed: {}", e))
    })?;

    let server_pubkey = noise
        .get_remote_static()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Server static key not received"))?;
    let mut server_static = [0u8; 32];
    server_static.copy_from_slice(server_pubkey);

    // -> s, se, ENCRYPTED[claim]
    let payload_bytes = bincode::serde::encode_to_vec(&claim, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let len = noise.write_message(&payload_bytes, &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise write_message failed: {}", e))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    let transport = noise.into_transport_mode().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to enter transport mode: {}", e))
    })?;

    Ok((transport, server_static))
}

/// Internal implementation of server handshake without error sending.
async fn noise_xx_server_impl<S>(
    stream: &mut S,
    server_key: &ServerKey,
) -> io::Result<(TransportState, PublicIdentity)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let pattern = NOISE_PATTERN.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Invalid Noise pattern: {}", e))
    })?;

    let mut noise = Builder::new(pattern)
        .local_private_key(server_key.private_key())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Noise local_private_key failed: {}", e)))?
        .build_responder()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Noise init failed: {}", e)))?;

    let mut buf = vec![0u8; MAX_HANDSHAKE_MESSAGE];

    // <- e
    let len = stream.read_u16().await? as usize;
    if len > MAX_HANDSHAKE_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Noise message too large"));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    noise.read_message(&msg, &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise read_message failed: {}", e))
    })?;

    // -> e, ee, s, es
    let len = noise.write_message(&[], &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise write_message failed: {}", e))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    // <- s, se, ENCRYPTED[claim]
    let len = stream.read_u16().await? as usize;
    if len > MAX_HANDSHAKE_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Noise message too large"));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    let payload_len = noise.read_message(&msg, &mut buf).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Noise read_message failed: {}", e))
    })?;

    let client_curve25519 = noise
        .get_remote_static()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Client static key not received"))?;

    let (claim, _): (Claim, _) = bincode::serde::decode_from_slice(&buf[..payload_len], bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Derive Ed25519 public key from the Noise Curve25519 static key
    // Conversion is ambiguous (missing sign bit), so we try both possibilities
    use curve25519_dalek::montgomery::MontgomeryPoint;

    let mut client_curve25519_bytes = [0u8; 32];
    client_curve25519_bytes.copy_from_slice(client_curve25519);
    let client_montgomery = MontgomeryPoint(client_curve25519_bytes);

    let verifying_key = {
        // Try sign bit = 0
        if let Some(edwards) = client_montgomery.to_edwards(0) {
            if let Ok(key) = VerifyingKey::from_bytes(&edwards.compress().to_bytes()) {
                if claim.verify(&key).is_ok() {
                    key
                } else {
                    // Try sign bit = 1
                    let edwards_alt = client_montgomery.to_edwards(1)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Cannot convert Curve25519 to Ed25519"))?;
                    let key_alt = VerifyingKey::from_bytes(&edwards_alt.compress().to_bytes())
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid Ed25519 public key"))?;
                    claim.verify(&key_alt)
                        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("Claim verification failed: {:?}", e)))?;
                    key_alt
                }
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Ed25519 public key"));
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Cannot convert Curve25519 to Ed25519"));
        }
    };

    let handle = claim.handle();
    let identity = PublicIdentity::from_verified_claim(verifying_key, handle);

    let transport = noise.into_transport_mode().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to enter transport mode: {}", e))
    })?;

    Ok((transport, identity))
}

/// Server-side Noise_XX handshake. Verifies claim and returns authenticated identity.
/// On error, sends a ServerError message to the client before returning.
pub async fn noise_xx_server<S>(
    stream: &mut S,
    server_key: &ServerKey,
) -> io::Result<(TransportState, PublicIdentity)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match noise_xx_server_impl(stream, server_key).await {
        Ok(result) => Ok(result),
        Err(e) => {
            // Send error message to client (best effort)
            use crate::protocol::ServerError;
            let error = ServerError::new(e.to_string());
            let _ = error.write(stream).await;
            Err(e)
        }
    }
}

/// Wraps a stream with Noise encryption.
/// Provides a transparent streaming interface - arbitrary data is automatically
/// chunked into 65KB Noise messages on write and reassembled on read.
pub struct NoiseStream<S> {
    stream: S,
    transport: TransportState,
    // Read buffer: decrypted plaintext waiting to be consumed
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> NoiseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, transport: TransportState) -> Self {
        Self {
            stream,
            transport,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Send an error message over the encrypted stream and flush.
    pub async fn send_error(&mut self, error_msg: &str) -> io::Result<()> {
        use crate::protocol::ServerError;
        let error = ServerError::new(error_msg);
        let encoded = bincode::serde::encode_to_vec(&error, bincode::config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.write_all(&encoded).await?;
        self.flush().await
    }

    /// Try to read an error message from the encrypted stream.
    /// Returns None if the data is not a valid ServerError packet.
    pub async fn try_read_error(&mut self) -> io::Result<Option<String>> {
        use crate::protocol::ServerError;

        // Try to read some data
        let mut buf = vec![0u8; 8192];
        let n = self.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }

        // Try to decode as ServerError
        match bincode::serde::decode_from_slice::<ServerError, _>(&buf[..n], bincode::config::standard()) {
            Ok((error, _)) => Ok(Some(error.message)),
            Err(_) => Ok(None),
        }
    }

    /// Read data from the encrypted stream, automatically decrypting Noise messages.
    /// Returns up to `buf.len()` bytes of plaintext.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we have buffered data, return it
        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;

            // Clear buffer if fully consumed
            if self.read_pos == self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }

            return Ok(to_copy);
        }

        // Need to read and decrypt a Noise message
        let chunk_len = self.stream.read_u16().await? as usize;
        if chunk_len == 0 {
            return Ok(0); // EOF
        }
        if chunk_len > MAX_NOISE_CIPHERTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Noise chunk too large: {} > {}", chunk_len, MAX_NOISE_CIPHERTEXT),
            ));
        }

        let mut encrypted = vec![0u8; chunk_len];
        self.stream.read_exact(&mut encrypted).await?;

        let mut decrypted = vec![0u8; MAX_NOISE_PLAINTEXT];
        let decrypted_len = self
            .transport
            .read_message(&encrypted, &mut decrypted)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Noise decrypt: {}", e)))?;

        // Copy what fits into the output buffer
        let to_copy = buf.len().min(decrypted_len);
        buf[..to_copy].copy_from_slice(&decrypted[..to_copy]);

        // Buffer any remaining data
        if to_copy < decrypted_len {
            self.read_buf = decrypted[to_copy..decrypted_len].to_vec();
            self.read_pos = 0;
        }

        Ok(to_copy)
    }

    /// Write data to the encrypted stream, automatically chunking into Noise messages.
    /// All data is sent immediately (no buffering).
    pub async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut offset = 0;
        while offset < buf.len() {
            let chunk_size = (buf.len() - offset).min(MAX_NOISE_PLAINTEXT);
            let chunk = &buf[offset..offset + chunk_size];

            let mut encrypted = vec![0u8; MAX_NOISE_CIPHERTEXT];
            let encrypted_len = self
                .transport
                .write_message(chunk, &mut encrypted)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Noise encrypt: {}", e)))?;

            self.stream.write_u16(encrypted_len as u16).await?;
            self.stream.write_all(&encrypted[..encrypted_len]).await?;

            offset += chunk_size;
        }

        self.stream.flush().await?;
        Ok(buf.len())
    }

    /// Write all data from the buffer, chunking as necessary.
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).await?;
        Ok(())
    }

    /// Flush the underlying stream.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
    }

    /// Copy all data bidirectionally between this encrypted stream and a plaintext stream.
    /// Continues until either stream closes.
    pub async fn copy_bidirectional<P>(self, plaintext: &mut P) -> io::Result<()>
    where
        P: AsyncRead + AsyncWrite + Unpin,
    {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let (mut plain_read, mut plain_write) = tokio::io::split(plaintext);
        let (stream, transport) = (self.stream, self.transport);
        let (mut enc_read, mut enc_write) = tokio::io::split(stream);

        // Wrap transport in Arc<Mutex> to share between tasks
        let transport = Arc::new(Mutex::new(transport));
        let transport_clone = transport.clone();

        let plaintext_to_encrypted = async move {
            loop {
                // Read plaintext
                let mut buf = vec![0u8; MAX_NOISE_PLAINTEXT];
                let n = plain_read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<(), io::Error>(());
                }

                // Encrypt and send as Noise message
                let mut encrypted = vec![0u8; MAX_NOISE_CIPHERTEXT];
                let encrypted_len = {
                    let mut transport = transport.lock().await;
                    transport
                        .write_message(&buf[..n], &mut encrypted)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Noise encrypt: {}", e)))?
                };

                enc_write.write_u16(encrypted_len as u16).await?;
                enc_write.write_all(&encrypted[..encrypted_len]).await?;
                enc_write.flush().await?;
            }
        };

        let encrypted_to_plaintext = async move {
            loop {
                // Read encrypted Noise message
                let chunk_len = enc_read.read_u16().await? as usize;
                if chunk_len == 0 {
                    return Ok::<(), io::Error>(());
                }
                if chunk_len > MAX_NOISE_CIPHERTEXT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Noise chunk too large: {} > {}", chunk_len, MAX_NOISE_CIPHERTEXT),
                    ));
                }

                let mut encrypted = vec![0u8; chunk_len];
                enc_read.read_exact(&mut encrypted).await?;

                // Decrypt and write plaintext
                let mut decrypted = vec![0u8; MAX_NOISE_PLAINTEXT];
                let decrypted_len = {
                    let mut transport = transport_clone.lock().await;
                    transport
                        .read_message(&encrypted, &mut decrypted)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Noise decrypt: {}", e)))?
                };

                plain_write.write_all(&decrypted[..decrypted_len]).await?;
                plain_write.flush().await?;
            }
        };

        tokio::select! {
            result = plaintext_to_encrypted => result,
            result = encrypted_to_plaintext => result,
        }
    }
}
