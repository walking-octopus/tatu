use crate::identity::{Identity, ServerKey};
use std::path::Path;
use tokio::fs;

/// Internal helper: Load or generate a 32-byte key from a file.
///
/// Keys are stored as raw 32 bytes (compatible with Curve25519).
/// Use `load_or_generate_identity()` or `load_or_generate_server_key()` instead.
async fn load_or_generate_key_bytes(path: &str) -> std::io::Result<[u8; 32]> {
    let path = Path::new(path);

    if path.exists() {
        let bytes = fs::read(path).await?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Key file must be exactly 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    } else {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        fs::write(path, &key).await?;
        Ok(key)
    }
}

/// Load or generate a client Identity (Ed25519) from a file.
///
/// Returns an Identity directly, avoiding the need to convert from raw bytes.
pub async fn load_or_generate_identity(path: &str) -> std::io::Result<Identity> {
    let key_bytes = load_or_generate_key_bytes(path).await?;
    Ok(Identity::from_bytes(&key_bytes))
}

/// Load or generate a ServerKey (Curve25519) from a file.
///
/// Returns a ServerKey that wraps both private and public keys.
pub async fn load_or_generate_server_key(path: &str) -> std::io::Result<ServerKey> {
    let key_bytes = load_or_generate_key_bytes(path).await?;
    Ok(ServerKey::from_bytes(&key_bytes))
}
