use azalea::protocol::{
    connect::Connection,
    packets::{
        handshake::{ClientboundHandshakePacket, ServerboundHandshakePacket},
        login::ServerboundLoginPacket,
        ClientIntention,
    },
};
use tatu_common::{ClientHello, ServerChallenge, ClientResponse};

use clap::Parser;
use std::path::Path;
use tatu_common::Identity;
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{Level, error, info};

mod claim;

#[derive(Parser, Debug)]
#[command(author, version, about = "Tatu client proxy", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:25565")]
    listen: String,

    #[arg(short, long, default_value = "127.0.0.1:25519")]
    server: String,

    #[arg(short, long, default_value = "./tatu-id.key")]
    key: String,
}

async fn load_or_generate_identity(key_path: &str) -> anyhow::Result<Identity> {
    let path = Path::new(key_path);

    if path.exists() {
        info!("Loading existing identity from {}", key_path);
        let key_bytes = fs::read(path).await?;

        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid key file: expected 32 bytes, got {}",
                key_bytes.len()
            ));
        }

        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&key_bytes);
        let identity = Identity::from_bytes(&secret_key);

        info!("Loaded identity: pubkey={:02x?}...", &identity.verifying_key().to_bytes()[..8]);
        Ok(identity)
    } else {
        info!("Generating new identity keypair...");
        let identity = Identity::generate();

        fs::write(path, &identity.to_bytes()).await?;
        info!("Saved new identity to {}", key_path);
        info!("Generated identity: pubkey={:02x?}...", &identity.verifying_key().to_bytes()[..8]);

        Ok(identity)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();
    let identity = load_or_generate_identity(&args.key).await?;

    let listener = TcpListener::bind(&args.listen).await?;
    info!("Client proxy listening on {}, connecting to server proxy at {}", args.listen, args.server);

    let server_addr = args.server.clone();
    loop {
        let (stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let server_addr = server_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, identity, &server_addr).await {
                error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(client_stream: TcpStream, identity: Identity, server_addr: &str) -> anyhow::Result<()> {
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

    let client_hello = ClientHello::new(&identity, claim);
    client_hello.write(&mut server_stream).await?;

    let server_challenge = ServerChallenge::read(&mut server_stream).await?;
    let response = ClientResponse::sign_challenge(&server_challenge, &identity);
    response.write(&mut server_stream).await?;

    let mut server_conn: Connection<ClientboundHandshakePacket, ServerboundHandshakePacket> =
        Connection::wrap(server_stream);
    server_conn.write(handshake_packet).await?;

    let mut server_conn = server_conn.login();
    server_conn.write(hello).await?;

    let mut client_stream = login_conn.unwrap()?;
    let mut server_stream = server_conn.unwrap()?;

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut server_read, mut server_write) = server_stream.split();

    let client_to_server = async {
        io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await
    };

    let server_to_client = async {
        io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}
