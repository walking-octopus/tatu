use base58::{FromBase58, ToBase58};
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Key file has world-accessible permissions (mode: {0:o}). Use chmod 600 to fix.")]
    WorldAccessible(u32),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

impl From<KeyError> for io::Error {
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::Io(io_err) => io_err,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

pub fn friendly_pub(key: &x25519::PublicKey) -> String {
    key.as_bytes().to_base58()
}

pub fn parse_public_key_base58(s: &str) -> Result<x25519::PublicKey, KeyError> {
    let bytes = s.from_base58()
        .map_err(|e| KeyError::InvalidBase58(format!("{:?}", e)))?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength(bytes.len()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(x25519::PublicKey::from(key_bytes))
}

#[cfg(unix)]
fn check_key_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    if mode & 0o004 != 0 {
        return Err(KeyError::WorldAccessible(mode));
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(path: &Path) -> Result<(), KeyError> {
    Ok(())
}

pub fn load_key(path: &Path) -> io::Result<x25519::StaticSecret> {
    check_key_permissions(path)?;

    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key file must be exactly 32 bytes",
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(x25519::StaticSecret::from(key_bytes))
}

pub fn save_key(path: &Path, secret: &x25519::StaticSecret) -> io::Result<()> {
    fs::write(path, secret.to_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // rw------- (owner read/write only)
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

pub fn gen_key() -> x25519::StaticSecret {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    x25519::StaticSecret::from(bytes)
}

pub fn load_or_gen(path: &Path) -> io::Result<x25519::StaticSecret> {
    if path.exists() {
        load_key(path)
    } else {
        let secret = gen_key();
        save_key(path, &secret)?;
        Ok(secret)
    }
}

// TODO: Mnemonic backup/recovery (BIP39-style)
// This would allow users to backup/restore their master key using a 24-word phrase
// pub fn backup_key(secret: &x25519::StaticSecret) -> [String; 24] { todo!() }
// pub fn restore_key(words: &[String; 24]) -> Result<x25519::StaticSecret, MnemonicError> { todo!() }

// NOTE: How do I print these to server operator on first launch without getting them logged?
// The client side should probably interactively ask to input 2 random nths to verify you wrote down the phrase
