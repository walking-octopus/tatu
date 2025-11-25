use crate::identity::{Claim, Identity, PublicIdentity};
use crate::protocol::ClientHelloError;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;

/// Generic packet read/write for length-prefixed bincode messages.
async fn write_packet<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    packet: &T,
) -> io::Result<()> {
    let encoded = bincode::serde::encode_to_vec(packet, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let len = encoded.len() as u32;
    writer.write_u32(len).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;

    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    max_size: u32,
    packet_name: &str,
) -> io::Result<T> {
    let len = reader.read_u32().await?;

    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} packet too large: {} bytes", packet_name, len),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map(|(result, _)| result)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub pubkey: [u8; 32],
    pub claim: Claim,
}

impl ClientHello {
    pub const VERSION: u8 = 1;

    pub fn new(identity: &Identity, claim: Claim) -> Self {
        Self {
            version: Self::VERSION,
            pubkey: identity.verifying_key().to_bytes(),
            claim,
        }
    }

    pub fn verify(&self) -> Result<PublicIdentity, ClientHelloError> {
        let verifying_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|_| ClientHelloError::InvalidPublicKey)?;

        self.claim.verify(&verifying_key)
            .map_err(ClientHelloError::ClaimVerification)?;

        let handle = self.claim.handle();
        Ok(PublicIdentity::from_verified_claim(verifying_key, handle))
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        write_packet(writer, self).await
    }

    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        read_packet(reader, 1024 * 1024, "ClientHello").await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerChallenge {
    pub nonce: [u8; 32],
}

impl ServerChallenge {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self { nonce }
    }

    pub fn verify_response(
        &self,
        response: &ClientResponse,
        identity: &PublicIdentity,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let signature = Signature::from_bytes(&response.signature);
        identity.verifying_key().verify(&self.nonce, &signature)
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        write_packet(writer, self).await
    }

    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        read_packet(reader, 1024 * 1024, "ServerChallenge").await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientResponse {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl ClientResponse {
    pub fn sign_challenge(challenge: &ServerChallenge, identity: &Identity) -> Self {
        let signature = identity.signing_key().sign(&challenge.nonce);
        Self {
            signature: signature.to_bytes(),
        }
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        write_packet(writer, self).await
    }

    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        read_packet(reader, 1024 * 1024, "ClientResponse").await
    }
}
