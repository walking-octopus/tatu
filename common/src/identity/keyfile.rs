use std::path::Path;
use tokio::fs;

/// Load or generate a 32-byte key from a file.
///
/// Used for both client identity keys and server static keys.
/// Keys are stored as raw 32 bytes (compatible with Curve25519).
pub async fn load_or_generate_key(path: &str) -> std::io::Result<[u8; 32]> {
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
