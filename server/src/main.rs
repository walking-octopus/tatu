use azalea::protocol::{
    connect::Connection,
    packets::{
        handshake::{
            ClientboundHandshakePacket, ServerboundHandshakePacket,
            s_intention::ServerboundIntention,
        },
        login::{ServerboundLoginPacket, s_hello::ServerboundHello},
        ClientIntention,
    },
    read::ReadPacketError,
};
use tatu_common::{ClientHello, ClientResponse, ServerChallenge};

use clap::Parser;

use futures::FutureExt;
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{Level, error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Tatu server proxy", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:25519")]
    listen: String,

    #[arg(short, long, default_value = "127.0.0.1:25564")]
    proxy: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await?;
    info!("Listening on {}, proxying to {}", args.listen, args.proxy);

    let proxy_addr = args.proxy.clone();
    loop {
        let (stream, _) = listener.accept().await?;
        let proxy_addr = proxy_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &proxy_addr).await {
                error!("Connection handler error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, proxy_addr: &str) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let ip = stream.peer_addr()?;

    let client_hello = ClientHello::read(&mut stream).await?;
    info!("Connection from {}: nick='{}'", ip.ip(), client_hello.claim.nick());

    let identity = client_hello.verify()?;

    let challenge = ServerChallenge::generate();
    challenge.write(&mut stream).await?;

    let response = ClientResponse::read(&mut stream).await?;
    challenge.verify_response(&response, &identity)
        .map_err(|e| anyhow::anyhow!("Challenge-response verification failed: {}", e))?;

    info!("Authenticated: {}", identity);

    let mut conn: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket> =
        Connection::wrap(stream);

    let intent = match conn.read().await {
        Ok(ServerboundHandshakePacket::Intention(packet)) => packet,
        Err(e) => return Err(e.into()),
    };

    if let ClientIntention::Login = intent.intention {
        let mut conn = conn.login();
        loop {
            match conn.read().await {
                Ok(ServerboundLoginPacket::Hello(mut hello)) => {
                    hello.profile_id = identity.uuid();
                    hello.name = identity.handle().to_string();

                    let proxy_addr = proxy_addr.to_string();
                    tokio::spawn(transfer(conn.unwrap()?, intent, hello, proxy_addr).map(|r| {
                        if let Err(e) = r {
                            error!("Proxy error: {e}");
                        }
                    }));
                    break;
                }
                Ok(_) => continue,
                Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => break,
                Err(e) => return Err(e.into()),
            }
        }
    }

    Ok(())
}

async fn transfer(
    mut inbound: TcpStream,
    intent: ServerboundIntention,
    hello: ServerboundHello,
    proxy_addr: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = hello.name.clone();

    let outbound = TcpStream::connect(&proxy_addr).await?;
    outbound.set_nodelay(true)?;
    outbound.set_quickack(true)?;

    let mut outbound_conn: Connection<ClientboundHandshakePacket, ServerboundHandshakePacket> =
        Connection::wrap(outbound);
    outbound_conn.write(intent).await?;

    let mut outbound_conn = outbound_conn.login();
    outbound_conn.write(hello).await?;
    let mut outbound = outbound_conn.unwrap()?;

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    info!("{} disconnected", name);

    Ok(())
}
