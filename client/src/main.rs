use azalea::protocol::{
    connect::Connection,
    packets::{
        handshake::{ClientboundHandshakePacket, ServerboundHandshakePacket},
        login::ServerboundLoginPacket,
        ClientIntention,
    },
};
use tatu_common::{noise_xx_client, NoiseStream, PacketBatch};

use clap::Parser;
use tatu_common::Identity;

mod claim;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Level, error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Tatu client proxy", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:25565")]
    listen: String,

    #[arg(short, long, default_value = "127.0.0.1:25519")]
    server: String,

    #[arg(short, long, default_value = "./tatu-id.key")]
    key: String,

    #[arg(short, long, default_value = "./tatu-servers.pin")]
    pins: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();

    let key_bytes = tatu_common::keyfile::load_or_generate_key(&args.key).await?;
    let identity = Identity::from_bytes(&key_bytes);
    let pubkey_b58 = bs58::encode(identity.verifying_key().to_bytes()).into_string();
    info!("Identity: {} (uuid: {})", pubkey_b58, identity.uuid());

    let listener = TcpListener::bind(&args.listen).await?;
    info!("Client proxy listening on {}, connecting to server proxy at {}", args.listen, args.server);

    let server_addr = args.server.clone();
    let pins_path = args.pins.clone();
    loop {
        let (stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let server_addr = server_addr.clone();
        let pins_path = pins_path.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, identity, &server_addr, &pins_path).await {
                error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(client_stream: TcpStream, identity: Identity, server_addr: &str, pins_path: &str) -> anyhow::Result<()> {
    client_stream.set_nodelay(true)?;
    let mut client_conn: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket> =
        Connection::wrap(client_stream);

    let handshake_packet = client_conn.read().await?;
    let intent = match &handshake_packet {
        ServerboundHandshakePacket::Intention(intent) => intent.clone(),
    };

    if !matches!(intent.intention, ClientIntention::Login) {
        return Ok(());
    }

    let mut login_conn = client_conn.login();
    let hello = match login_conn.read().await? {
        ServerboundLoginPacket::Hello(hello) => hello,
        _ => return Ok(()),
    };

    let mut server_stream = TcpStream::connect(server_addr).await?;
    server_stream.set_nodelay(true)?;
    server_stream.set_quickack(true)?;

    let claim = claim::load_or_mine_claim(&hello.name, &identity).await?;

    // TODO(client): 32 sec > timeout, when identity not mined, maybe we can emulate an MCProto kick/error message for please hold?

    let (transport, server_static_key) = noise_xx_client(&mut server_stream, &identity, &claim).await?;

    // Verify or pin the server's public key (TOFU)
    let server_pubkey_b58 = bs58::encode(&server_static_key).into_string();
    let is_new = tatu_common::pinning::verify_or_pin(
        std::path::Path::new(pins_path),
        server_addr,
        &server_static_key
    ).await?;

    if is_new {
        info!("New server pinned: {} -> {}", server_addr, server_pubkey_b58);
    } else {
        info!("Server verified: {} -> {}", server_addr, server_pubkey_b58);
    }

    // Wrap the server stream with Noise encryption
    let mut noise_stream = NoiseStream::new(server_stream, transport);

    // -1 RTT: batch handshake + login in single encrypted write
    let batch_bytes = PacketBatch::new()
        .add(handshake_packet)?
        .add(hello.clone())?
        .into_bytes();
    noise_stream.write_all(&batch_bytes).await?;

    // Get the raw Minecraft client stream
    let mut client_stream = login_conn.unwrap()?;

    // Forward all traffic bidirectionally through transparent Noise encryption
    noise_stream.copy_bidirectional(&mut client_stream).await?;

    Ok(())
}
