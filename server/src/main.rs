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
    let server_static_key = tatu_common::keyfile::load_or_generate_key(&args.key).await?;
    info!("Server static key loaded from {}", args.key);

    let listener = TcpListener::bind(&args.listen).await?;
    info!("Listening on {}, proxying to {}", args.listen, args.proxy);

    let proxy_addr = args.proxy.clone();
    loop {
        let (stream, _) = listener.accept().await?;
        let proxy_addr = proxy_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &proxy_addr, &server_static_key).await {
                error!("Connection handler error: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    proxy_addr: &str,
    server_static_key: &[u8; 32],
) -> anyhow::Result<()> {
    let mut stream = stream;
    stream.set_nodelay(true)?;
    stream.set_quickack(true)?;
    let ip = stream.peer_addr()?;

    let (transport, identity) = noise_xx_server(&mut stream, server_static_key).await?;
    info!("Authenticated {} ({}) from {}", identity, identity.uuid().as_hyphenated(), ip.ip());

    // Wrap with Noise encryption
    let mut noise_stream = NoiseStream::new(stream, transport);

    // Read initial batched handshake+login from client (encrypted)
    // Read enough bytes for both packets
    let mut initial_batch = vec![0u8; 8192];
    let n = noise_stream.read(&mut initial_batch).await?;
    initial_batch.truncate(n);

    // Parse packets manually from decrypted batch
    use tokio::io::AsyncReadExt;
    let mut cursor = std::io::Cursor::new(&initial_batch);

    // VarInt-framed packet parsing
    let handshake_len = read_varint(&mut cursor).await?;
    let mut handshake_data = vec![0u8; handshake_len as usize];
    cursor.read_exact(&mut handshake_data).await?;

    // Parse handshake packet
    let mut handshake_cursor = std::io::Cursor::new(&handshake_data);
    let packet_id = read_varint(&mut handshake_cursor).await?;
    if packet_id != 0x00 {
        return Err(anyhow::anyhow!("Expected handshake packet, got ID {:#x}", packet_id));
    }

    // Parse handshake fields
    let protocol_version = read_varint(&mut handshake_cursor).await?;
    let hostname = read_string(&mut handshake_cursor).await?;
    let port = handshake_cursor.read_u16().await?;
    let intention_value = read_varint(&mut handshake_cursor).await?;

    let intention = match intention_value {
        1 => azalea::protocol::packets::ClientIntention::Status,
        2 => azalea::protocol::packets::ClientIntention::Login,
        3 => azalea::protocol::packets::ClientIntention::Transfer,
        _ => return Err(anyhow::anyhow!("Unknown intention {}", intention_value)),
    };

    // Only handle login intention for now
    if !matches!(intention, azalea::protocol::packets::ClientIntention::Login) {
        return Err(anyhow::anyhow!("Only login intention is supported"));
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
    noise_stream.copy_bidirectional(&mut backend).await?;

    info!("Connection from {} closed", identity);
    Ok(())
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
