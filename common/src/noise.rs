use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use snow::{Builder, HandshakeState, TransportState};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed, LengthDelimitedCodec};

// NOTE: COGDEBT: Frame/Sink/Codec

const MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const MAX_PLAIN: usize = MAX_MSG - TAG_LEN - 1;
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

fn length_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .little_endian()
        .max_frame_length(MAX_MSG)
        .new_codec()
}

pub struct NoiseCodec {
    pub transport: TransportState,
    pending: BytesMut,
    decode_buf: BytesMut,
    encode_buf: BytesMut,
}

impl Decoder for NoiseCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let decode_start = std::time::Instant::now();
        let result = loop {
            if src.len() < 2 {
                return Ok(None);
            }
            let len = u16::from_le_bytes([src[0], src[1]]) as usize;
            if src.len() < 2 + len {
                src.reserve(2 + len - src.len());
                return Ok(None);
            }

            src.advance(2);
            let ciphertext = src.split_to(len);

            self.decode_buf.clear();
            self.decode_buf.resize(len, 0);

            let n = self
                .transport
                .read_message(&ciphertext, &mut self.decode_buf)
                .map_err(io_err)?;

            if n == 0 {
                return Err(io_err("empty chunk"));
            }

            self.pending.put_slice(&self.decode_buf[1..n]);

            match self.decode_buf[0] {
                0 => break Ok(Some(std::mem::take(&mut self.pending).freeze())),
                1 => continue,
                f => return Err(io_err(format!("invalid flag: {f}"))),
            }
        };
        let decode_time = decode_start.elapsed();
        if decode_time.as_millis() > 1 {
            if let Ok(Some(ref bytes)) = result {
                tracing::warn!("DECODE SLOW: {:?} size={}", decode_time, bytes.len());
            }
        }
        result
    }
}

impl Encoder<Bytes> for NoiseCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        let encode_start = std::time::Instant::now();
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(MAX_PLAIN).collect()
        };
        let last = chunks.len() - 1;

        for (i, chunk) in chunks.iter().enumerate() {
            let flag = if i < last { 1u8 } else { 0u8 };

            self.encode_buf.clear();
            self.encode_buf.put_u8(flag);
            self.encode_buf.put_slice(chunk);

            let max_out = self.encode_buf.len() + TAG_LEN;
            dst.reserve(2 + max_out);

            let len_pos = dst.len();
            dst.put_slice(&[0, 0]);

            let cipher_start = dst.len();
            dst.resize(cipher_start + max_out, 0);

            let n = self
                .transport
                .write_message(&self.encode_buf, &mut dst[cipher_start..])
                .map_err(io_err)?;

            dst.truncate(cipher_start + n);

            let len_bytes = (n as u16).to_le_bytes();
            dst[len_pos..len_pos + 2].copy_from_slice(&len_bytes);
        }
        let encode_time = encode_start.elapsed();
        if encode_time.as_millis() > 1 {
            tracing::warn!("ENCODE SLOW: {:?} size={}", encode_time, data.len());
        }
        Ok(())
    }
}

pub struct NoisePipe<T>(Framed<T, NoiseCodec>);

impl<T: AsyncRead + AsyncWrite + Unpin> NoisePipe<T> {
    pub async fn connect(stream: T, secret: &x25519::StaticSecret) -> io::Result<Self> {
        let hs = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&secret.to_bytes())
            .map_err(io_err)?
            .build_initiator()
            .map_err(io_err)?;
        handshake(stream, hs).await
    }

    pub async fn accept(stream: T, secret: &x25519::StaticSecret) -> io::Result<Self> {
        let hs = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&secret.to_bytes())
            .map_err(io_err)?
            .build_responder()
            .map_err(io_err)?;
        handshake(stream, hs).await
    }

    pub fn remote_public_key(&self) -> io::Result<x25519::PublicKey> {
        let remote = self
            .0
            .codec()
            .transport
            .get_remote_static()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no remote static key"))?;
        let key_bytes: [u8; 32] = remote.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "remote static key must be 32 bytes",
            )
        })?;
        Ok(x25519::PublicKey::from(key_bytes))
    }

    pub fn transport(&self) -> &TransportState {
        &self.0.codec().transport
    }
    pub fn transport_mut(&mut self) -> &mut TransportState {
        &mut self.0.codec_mut().transport
    }
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
    pub fn get_ref(&self) -> &T {
        self.0.get_ref()
    }
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> NoisePipe<T> {
    pub fn split(
        self,
    ) -> (
        futures::stream::SplitSink<Framed<T, NoiseCodec>, Bytes>,
        futures::stream::SplitStream<Framed<T, NoiseCodec>>,
    ) {
        self.0.split()
    }
}

impl<T: AsyncRead + Unpin> futures::Stream for NoisePipe<T> {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

impl<T: AsyncWrite + Unpin> futures::Sink<Bytes> for NoisePipe<T> {
    type Error = io::Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        Pin::new(&mut self.0).start_send(item)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

async fn handshake<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    mut hs: HandshakeState,
) -> io::Result<NoisePipe<T>> {
    let mut framed = Framed::new(stream, length_codec());
    let mut buf = vec![0u8; MAX_MSG];

    while !hs.is_handshake_finished() {
        if hs.is_my_turn() {
            let n = hs.write_message(&[], &mut buf).map_err(io_err)?;
            framed.send(Bytes::copy_from_slice(&buf[..n])).await?;
        } else {
            let msg = framed
                .next()
                .await
                .ok_or_else(|| io_err("connection closed during handshake"))??;
            hs.read_message(&msg, &mut buf).map_err(io_err)?;
        }
    }

    let transport = hs.into_transport_mode().map_err(io_err)?;
    let inner = framed.into_inner();
    Ok(NoisePipe(Framed::new(
        inner,
        NoiseCodec {
            transport,
            pending: BytesMut::new(),
            decode_buf: BytesMut::with_capacity(MAX_MSG),
            encode_buf: BytesMut::with_capacity(MAX_PLAIN + 1),
        },
    )))
}

fn io_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use tokio::net::{TcpListener, TcpStream};

    pub fn generate_keypair() -> x25519::StaticSecret {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        x25519::StaticSecret::from(bytes)
    }

    async fn setup() -> io::Result<(NoisePipe<TcpStream>, NoisePipe<TcpStream>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let client_key = generate_keypair();
        let server_key = generate_keypair();

        let client = tokio::spawn({
            async move {
                let stream = TcpStream::connect(addr).await?;
                NoisePipe::connect(stream, &client_key).await
            }
        });

        let (stream, _) = listener.accept().await?;
        let server = NoisePipe::accept(stream, &server_key).await?;
        let client = client.await.unwrap()?;

        Ok((client, server))
    }

    #[tokio::test]
    async fn roundtrip_small() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        client.send(Bytes::from("hello")).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(&msg[..], b"hello");

        server.send(Bytes::from("world")).await?;
        let msg = client.next().await.unwrap()?;
        assert_eq!(&msg[..], b"world");

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_empty() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        client.send(Bytes::new()).await?;
        let msg = server.next().await.unwrap()?;
        assert!(msg.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_exactly_one_chunk() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xAB; MAX_PLAIN];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_one_byte_over_chunk() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xCD; MAX_PLAIN + 1];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN + 1);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_exactly_two_chunks() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xEF; MAX_PLAIN * 2];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN * 2);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_large_message() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload: Vec<u8> = (0..500_000).map(|i| i as u8).collect();
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), 500_000);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn multiple_messages_in_sequence() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        for i in 0u8..10 {
            let payload = vec![i; 1000 * (i as usize + 1)];
            client.send(Bytes::from(payload.clone())).await?;
            let msg = server.next().await.unwrap()?;
            assert_eq!(&msg[..], &payload[..]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn bidirectional_concurrent() -> io::Result<()> {
        let (client, server) = setup().await?;
        let (mut client_tx, mut client_rx) = client.split();
        let (mut server_tx, mut server_rx) = server.split();

        let c2s = tokio::spawn(async move {
            for i in 0u8..5 {
                client_tx.send(Bytes::from(vec![i; 10_000])).await.unwrap();
            }
        });

        let s2c = tokio::spawn(async move {
            for i in 0u8..5 {
                server_tx
                    .send(Bytes::from(vec![i + 100; 10_000]))
                    .await
                    .unwrap();
            }
        });

        let c_recv = tokio::spawn(async move {
            for i in 0u8..5 {
                let msg = client_rx.next().await.unwrap().unwrap();
                assert_eq!(msg.len(), 10_000);
                assert_eq!(msg[0], i + 100);
            }
        });

        let s_recv = tokio::spawn(async move {
            for i in 0u8..5 {
                let msg = server_rx.next().await.unwrap().unwrap();
                assert_eq!(msg.len(), 10_000);
                assert_eq!(msg[0], i);
            }
        });

        c2s.await.unwrap();
        s2c.await.unwrap();
        c_recv.await.unwrap();
        s_recv.await.unwrap();

        Ok(())
    }
}
