use std::path::{Path, PathBuf};
use tatu_common::{Claim, Identity};
use tokio::fs;
use tracing::info;

const CLAIMS_DIR: &str = "./tatu-nicks";

fn claim_path(nick: &str) -> PathBuf {
    Path::new(CLAIMS_DIR).join(format!("{}.claim", nick))
}

/// Load existing claim for nick, or mine a new one.
pub async fn load_or_mine_claim(nick: &str, identity: &Identity) -> anyhow::Result<Claim> {
    let path = claim_path(nick);

    if path.exists() {
        let claim_bytes = fs::read(&path).await?;
        let config = bincode::config::standard();

        if let Ok((claim, _)) = bincode::decode_from_slice::<Claim, _>(&claim_bytes, config) {
            if let Ok(_disc) = claim.verify(&identity.verifying_key()) {
                return Ok(claim);
            }
        }

        info!("Cached claim for '{}' doesn't match current keypair, re-mining", nick);
    }

    mine_new_claim(nick, identity).await
}

async fn mine_new_claim(nick: &str, identity: &Identity) -> anyhow::Result<Claim> {
    info!("Mining VDF proof for '{}' (this will take ~30 seconds)...", nick);

    let start = std::time::Instant::now();
    let claim = identity.mine_claim(nick);
    let elapsed = start.elapsed();

    let handle = claim.handle();
    info!("Mined '{}' in {:.2}s", handle, elapsed.as_secs_f64());

    fs::create_dir_all(CLAIMS_DIR).await?;
    let config = bincode::config::standard();
    let claim_bytes = bincode::encode_to_vec(&claim, config)?;
    fs::write(&claim_path(nick), claim_bytes).await?;

    Ok(claim)
}
