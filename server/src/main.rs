use tatu_common::{noise_xx_server, NoiseStream};

use azalea::protocol::{
    connect::Connection,
    packets::{
        handshake::{ClientboundHandshakePacket, ServerboundHandshakePacket},
        login::ServerboundLoginPacket,
    },
};

use clap::Parser;

use tokio::net::{TcpListener, TcpStream};
use tracing::{Level, error, info};

/// Extension trait to send errors over NoiseStream before returning them.
trait SendErrorExt<T, S> {
    async fn or_send_error(self, stream: &mut NoiseStream<S>) -> anyhow::Result<T>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin;
}

impl<T, S> SendErrorExt<T, S> for std::io::Result<T> {
    async fn or_send_error(self, stream: &mut NoiseStream<S>) -> anyhow::Result<T>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self {
            Ok(val) => Ok(val),
            Err(e) => {
                let _ = stream.send_error(&e.to_string()).await;
                Err(e.into())
            }
        }
    }
}

impl<T, S> SendErrorExt<T, S> for anyhow::Result<T> {
    async fn or_send_error(self, stream: &mut NoiseStream<S>) -> anyhow::Result<T>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self {
            Ok(val) => Ok(val),
            Err(e) => {
                let _ = stream.send_error(&e.to_string()).await;
                Err(e)
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Tatu server proxy", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:25519")]
    listen: String,

    #[arg(short, long, default_value = "127.0.0.1:25564")]
    proxy: String,

    #[arg(short, long, default_value = "./tatu-server.key")]
    key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();
    let server_key = tatu_common::identity::keyfile::load_or_generate_server_key(&args.key).await?;

    // Print server public key for out-of-band verification
    // Use Curve25519 public key (what clients see in Noise handshake)
    let server_pubkey_b58 = bs58::encode(server_key.public_key()).into_string();
    info!("Server identity loaded from {}", args.key);
    info!("Server identity: {}", server_pubkey_b58);
    info!("Share this on multiple independent platforms for out-of-band verification!");

    let listener = TcpListener::bind(&args.listen).await?;
    info!("Listening on {}, proxying to {}", args.listen, args.proxy);

    let proxy_addr = args.proxy.clone();
    loop {
        let (stream, _) = listener.accept().await?;
        let proxy_addr = proxy_addr.clone();
        let server_key = server_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &proxy_addr, &server_key).await {
                // Distinguish between normal disconnects and actual errors
                match e.downcast_ref::<std::io::Error>() {
                    Some(io_err) if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                                 || io_err.kind() == std::io::ErrorKind::ConnectionReset
                                 || io_err.kind() == std::io::ErrorKind::BrokenPipe => {
                        // Normal disconnect, already logged in handle_connection
                    }
                    _ => {
                        error!("Connection handler error: {e}");
                    }
                }
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    proxy_addr: &str,
    server_key: &tatu_common::identity::ServerKey,
) -> anyhow::Result<()> {
    let mut stream = stream;
    stream.set_nodelay(true)?;
    stream.set_quickack(true)?;
    let ip = stream.peer_addr()?;

    let (transport, identity) = noise_xx_server(&mut stream, server_key).await?;
    info!("Authenticated {} ({}) from {}", identity, identity.uuid().as_hyphenated(), ip.ip());

    // Wrap with Noise encryption
    let mut noise_stream = NoiseStream::new(stream, transport);

    // Read initial batched handshake+login from client (encrypted)
    // Read enough bytes for both packets
    let mut initial_batch = vec![0u8; 8192];
    let n = noise_stream.read(&mut initial_batch).await.or_send_error(&mut noise_stream).await?;
    initial_batch.truncate(n);

    // Parse packets manually from decrypted batch
    use tokio::io::AsyncReadExt;
    let mut cursor = std::io::Cursor::new(&initial_batch);

    // VarInt-framed packet parsing
    let handshake_len = read_varint(&mut cursor).await.or_send_error(&mut noise_stream).await?;
    let mut handshake_data = vec![0u8; handshake_len as usize];
    cursor.read_exact(&mut handshake_data).await.or_send_error(&mut noise_stream).await?;

    // Parse handshake packet
    let mut handshake_cursor = std::io::Cursor::new(&handshake_data);
    let packet_id = read_varint(&mut handshake_cursor).await.or_send_error(&mut noise_stream).await?;

    if packet_id != 0x00 {
        return Err(anyhow::anyhow!("Expected handshake packet, got ID {:#x}", packet_id))
            .or_send_error(&mut noise_stream).await;
    }

    // Parse handshake fields
    let protocol_version = read_varint(&mut handshake_cursor).await.or_send_error(&mut noise_stream).await?;
    let hostname = read_string(&mut handshake_cursor).await.or_send_error(&mut noise_stream).await?;
    let port = handshake_cursor.read_u16().await.or_send_error(&mut noise_stream).await?;
    let intention_value = read_varint(&mut handshake_cursor).await.or_send_error(&mut noise_stream).await?;

    let intention = match intention_value {
        1 => azalea::protocol::packets::ClientIntention::Status,
        2 => azalea::protocol::packets::ClientIntention::Login,
        3 => azalea::protocol::packets::ClientIntention::Transfer,
        _ => return Err(anyhow::anyhow!("Unknown intention {}", intention_value))
            .or_send_error(&mut noise_stream).await,
    };

    // Only handle login intention for now
    if !matches!(intention, azalea::protocol::packets::ClientIntention::Login) {
        return Err(anyhow::anyhow!("Only login intention is supported"))
            .or_send_error(&mut noise_stream).await;
    }

    // Read login packet
    let login_len = read_varint(&mut cursor).await?;
    let mut login_data = vec![0u8; login_len as usize];
    cursor.read_exact(&mut login_data).await?;

    // Connect to backend
    let backend = TcpStream::connect(proxy_addr).await?;
    backend.set_nodelay(true)?;
    backend.set_quickack(true)?;

    let mut backend_conn: Connection<ClientboundHandshakePacket, ServerboundHandshakePacket> =
        Connection::wrap(backend);

    // Send modified handshake with BungeeCord forwarding
    let bungeecord_hostname = format!(
        "{}\0{}\0{}\0[]",
        hostname,
        ip.ip(),
        identity.uuid().as_hyphenated()
    );

    backend_conn.write(ServerboundHandshakePacket::Intention(
        azalea::protocol::packets::handshake::s_intention::ServerboundIntention {
            protocol_version,
            hostname: bungeecord_hostname,
            port,
            intention,
        }
    )).await?;

    // Switch to login state
    let mut backend_conn = backend_conn.login();

    // Parse and send modified login packet
    let mut login_cursor = std::io::Cursor::new(&login_data);
    let login_packet_id = read_varint(&mut login_cursor).await?;

    if login_packet_id == 0x00 {
        // Hello packet
        let _name = read_string(&mut login_cursor).await?;
        let _uuid = {
            let mut uuid_bytes = [0u8; 16];
            login_cursor.read_exact(&mut uuid_bytes).await?;
            uuid::Uuid::from_bytes(uuid_bytes)
        };

        backend_conn.write(ServerboundLoginPacket::Hello(
            azalea::protocol::packets::login::s_hello::ServerboundHello {
                name: identity.handle().to_string(),
                profile_id: identity.uuid(),
            }
        )).await?;
    } else {
        return Err(anyhow::anyhow!("Expected login hello packet, got ID {:#x}", login_packet_id));
    }

    // After sending login hello, unwrap immediately to avoid buffering issues
    // The backend will send login responses which we'll forward as raw packets
    let mut backend = backend_conn.unwrap()?;

    // Forward all subsequent traffic bidirectionally through transparent Noise encryption
    // noise_stream <-> backend (plaintext Minecraft)
    match noise_stream.copy_bidirectional(&mut backend).await {
        Ok(()) => {
            info!("Connection from {} closed cleanly", identity);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
               || e.kind() == std::io::ErrorKind::ConnectionReset
               || e.kind() == std::io::ErrorKind::BrokenPipe => {
            info!("Connection from {} closed", identity);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

async fn read_varint<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<i32> {
    use tokio::io::AsyncReadExt;
    let mut ans = 0;
    for i in 0..5 {
        let byte = reader.read_u8().await?;
        ans |= ((byte & 0b0111_1111) as i32) << (7 * i);
        if byte & 0b1000_0000 == 0 {
            return Ok(ans);
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "VarInt too long"))
}

async fn read_string<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    let len = read_varint(reader).await?;
    if len < 0 || len > 32767 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "String length out of bounds"));
    }
    let mut bytes = vec![0u8; len as usize];
    reader.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
