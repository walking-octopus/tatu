//! Server public key pinning (TOFU - Trust On First Use)
//!
//! Maintains a file of trusted server public keys in the format:
//! `<address> <base58-pubkey>\n`

use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Load pinned server public keys from a file.
/// Returns a map of address -> base58-encoded public key.
pub async fn load_pins(path: &Path) -> std::io::Result<HashMap<String, String>> {
    let mut pins = HashMap::new();

    if !path.exists() {
        return Ok(pins);
    }

    let file = fs::File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            pins.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    Ok(pins)
}

/// Add or update a pinned server public key.
pub async fn add_pin(path: &Path, address: &str, pubkey_b58: &str) -> std::io::Result<()> {
    let mut pins = load_pins(path).await?;
    pins.insert(address.to_string(), pubkey_b58.to_string());

    let mut content = String::new();
    for (addr, key) in pins {
        content.push_str(&format!("{} {}\n", addr, key));
    }

    fs::write(path, content).await
}

/// Verify a server's public key matches the pinned key, or pin it if first connection.
/// Returns Ok(true) if this was a new pin, Ok(false) if verified against existing pin.
pub async fn verify_or_pin(
    path: &Path,
    address: &str,
    pubkey: &[u8; 32],
) -> std::io::Result<bool> {
    let pubkey_b58 = bs58::encode(pubkey).into_string();
    let pins = load_pins(path).await?;

    match pins.get(address) {
        Some(pinned) if pinned == &pubkey_b58 => {
            // Key matches existing pin
            Ok(false)
        }
        Some(pinned) => {
            // Key mismatch - possible MITM attack
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Server public key mismatch for {}!\nExpected: {}\nReceived: {}\nPossible man-in-the-middle attack!",
                    address, pinned, pubkey_b58
                ),
            ))
        }
        None => {
            // First connection - pin the key
            add_pin(path, address, &pubkey_b58).await?;
            Ok(true)
        }
    }
}
