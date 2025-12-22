mod keychain;

use bytes::Bytes;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use keychain::Keychain;
use std::path::PathBuf;
use std::sync::Arc;
use tatu_common::keys::{RemoteTatuKey, TatuKey};
use tatu_common::noise::NoisePipe;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const MAX_NICK_LENGTH: usize = 7;

#[derive(Parser)]
#[command(about = "Tatu client proxy")]
struct Args {
    #[arg(default_value = "127.0.0.1:25519")]
    proxy_addr: String,

    #[arg(long, default_value = "127.0.0.1:25565")]
    listen_addr: String,

    #[arg(long = "skin")]
    skin_path: Option<PathBuf>,

    #[arg(long = "key", env = "TATU_KEY", default_value = "tatu-id.key")]
    key_path: PathBuf,

    #[arg(long = "handles", env = "TATU_HANDLE_CACHE", default_value = "tatu-handles")]
    handles_path: PathBuf,

    #[arg(long = "known-servers", env = "TATU_KNOWN_SERVERS", default_value = "tatu-servers.pin")]
    known_servers_path: PathBuf,
}

struct Runtime {
    proxy_addr: String,
    skin: Option<Arc<str>>,
    keychain: Mutex<Keychain>,
}

impl Runtime {
    fn load(args: &Args) -> anyhow::Result<Self> {
        let identity = Arc::new(TatuKey::load_or_generate(&args.key_path)?);

        let skin = args
            .skin_path
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .map(prob_json)
            .transpose()?
            .map(Into::into);

        let keychain = Keychain::new(identity, &args.handles_path, &args.known_servers_path)?;

        Ok(Self {
            proxy_addr: args.proxy_addr.clone(),
            skin,
            keychain: Mutex::new(keychain),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen_addr).await?;
    let runtime = Arc::new(Runtime::load(&args)?);

    tracing::info!(
        "Client proxy listening on {}, forwarding to {}",
        args.listen_addr,
        runtime.proxy_addr
    );

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, &runtime).await {
                tracing::error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_client(stream: TcpStream, rt: &Runtime) -> anyhow::Result<()> {
    let (mc_read, mc_write, nick) = read_mc_login(stream).await?;
    tracing::info!("Connecting as {nick}");

    let tcp_stream = TcpStream::connect(&rt.proxy_addr).await?;
    tcp_stream.set_nodelay(true)?;

    let x_key = rt.keychain.lock().await.identity.x_key();
    let mut secure_pipe = NoisePipe::connect(tcp_stream, &x_key).await?;

    let server_key = RemoteTatuKey::from_x_pub(secure_pipe.remote_public_key()?);

    let handle_claim = {
        let mut keychain = rt.keychain.lock().await;

        match keychain.id_server(&rt.proxy_addr, &server_key) {
            Ok(()) => {
                tracing::info!("Server key verified");
            }
            Err(keychain::PinError::NotKnown) => {
                tracing::warn!("Server not known, pinning key: {server_key}");
                keychain.pin_server(rt.proxy_addr.clone(), server_key)?;
                tracing::info!("Verify this key through a trusted channel!");
            }
            Err(keychain::PinError::Mismatch) => {
                anyhow::bail!("Server key mismatch! Potential MITM attack detected");
            }
        }

        keychain.get_handle(&nick)?
    };

    let auth_msg = tatu_common::model::AuthMessage {
        handle_claim,
        skin: rt.skin.as_deref().map(String::from),
    };

    secure_pipe
        .send(Bytes::from(rmp_serde::to_vec(&auth_msg)?))
        .await?;

    tracing::info!("Connected to proxy server");
    let result = forward_messages(mc_read, mc_write, secure_pipe).await;
    tracing::info!("Disconnected");

    result
}

fn prob_json(s: String) -> anyhow::Result<String> {
    let t = s.trim();

    if !t.starts_with('{') && !t.starts_with('[') {
        anyhow::bail!("Not JSON given");
    }
    if !t.ends_with('}') && !t.ends_with(']') {
        anyhow::bail!("JSON cut off");
    }
    if t.contains('{') && t.contains(':') && !t.contains("\":") {
        anyhow::bail!("Given SNBT, not JSON (tip: quote the fields)");
    }

    Ok(s)
}

async fn read_mc_login(
    stream: TcpStream,
) -> anyhow::Result<(
    azalea::protocol::connect::RawReadConnection,
    azalea::protocol::connect::RawWriteConnection,
    String,
)> {
    use azalea::protocol::{
        connect::Connection,
        packets::{handshake::ServerboundHandshakePacket, login::ServerboundLoginPacket},
        read::ReadPacketError,
    };

    let mut conn = Connection::wrap(stream);

    match conn.read().await {
        Ok(ServerboundHandshakePacket::Intention(_)) => {}
        Err(_) => anyhow::bail!("Failed to read handshake"),
    }

    let mut conn = conn.login();

    let hello = loop {
        match conn.read().await {
            Ok(ServerboundLoginPacket::Hello(h)) => break h,
            Ok(_) => continue,
            Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => {
                anyhow::bail!("Connection closed during login")
            }
            Err(e) => return Err(e.into()),
        }
    };

    let mut nick = hello.name.clone();
    nick.truncate(MAX_NICK_LENGTH);

    let (read, write) = conn.into_split_raw();
    Ok((read, write, nick))
}

async fn forward_messages(
    mut mc_read: azalea::protocol::connect::RawReadConnection,
    mut mc_write: azalea::protocol::connect::RawWriteConnection,
    proxy: NoisePipe<TcpStream>,
) -> anyhow::Result<()> {
    let (mut proxy_sink, mut proxy_stream) = proxy.split();

    loop {
        tokio::select! {
            mc_msg = mc_read.read() => {
                match mc_msg {
                    Ok(bytes) => {
                        proxy_sink.send(Bytes::from(bytes)).await?;
                        proxy_sink.flush().await?;
                    }
                    Err(e) if matches!(*e, azalea::protocol::read::ReadPacketError::ConnectionClosed) => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            proxy_msg = proxy_stream.next() => {
                match proxy_msg {
                    Some(Ok(bytes)) => {
                        mc_write.write(&bytes).await?;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                }
            }
        }
    }

    Ok(())
}
