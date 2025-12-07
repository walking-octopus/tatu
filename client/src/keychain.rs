use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use tatu_common::model::HandleClaim;
use thiserror::Error;
use x25519;

#[derive(Debug, Error)]
pub enum PinError {
    #[error("Server not known")]
    NotKnown,
    #[error("Server key mismatch")]
    Mismatch,
}

pub struct Keychain<'a> {
    pub identity: &'a x25519::StaticSecret,
    known_servers: HashMap<String, x25519::PublicKey>,

    handles_dir: PathBuf,
    servers_path: PathBuf,
}

impl<'a> Keychain<'a> {
    pub fn new(
        master_key: &'a x25519::StaticSecret,
        handles_dir: impl Into<PathBuf>,
        servers_path: impl Into<PathBuf>,
    ) -> io::Result<Self> {
        let servers_path = servers_path.into();
        let known_servers = Self::load_pins(&servers_path)?;

        Ok(Keychain {
            identity: master_key,
            known_servers,
            handles_dir: handles_dir.into(),
            servers_path,
        })
    }

    fn load_pins(path: &PathBuf) -> io::Result<HashMap<String, x25519::PublicKey>> {
        let mut pins = HashMap::new();
        if !path.exists() {
            return Ok(pins);
        }

        let content = fs::read_to_string(path)?;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid pin format on line {}: expected '<hostname> <base58-pubkey>'",
                        line_num + 1
                    ),
                ));
            }

            let hostname = parts[0].to_string();
            let pubkey = tatu_common::keys::parse_public_key_base58(parts[1]).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid key on line {}: {}", line_num + 1, e),
                )
            })?;

            pins.insert(hostname, pubkey);
        }

        Ok(pins)
    }

    fn save_pins(&self) -> io::Result<()> {
        let mut lines: Vec<String> = self
            .known_servers
            .iter()
            .map(|(host, key)| {
                let key_b58 = base58::ToBase58::to_base58(&key.as_bytes()[..]);
                format!("{} {}", host, key_b58)
            })
            .collect();

        lines.sort();
        let content = lines.join("\n") + "\n";

        fs::write(&self.servers_path, content)
    }

    pub fn get_handle(&self, nick: &str) -> io::Result<HandleClaim> {
        let file_path = self.handles_dir.join(format!("{}.nick", nick));
        let public_key = x25519::PublicKey::from(self.identity);

        let claim = match file_path.exists() {
            true => {
                let data = fs::read(&file_path)?;
                let claim: HandleClaim = rmp_serde::from_slice(&data)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                match claim.clone().verify(&public_key) {
                    Ok(_) => claim,
                    Err(_) => {
                        tracing::warn!("Invalid handle claim found for '{}', remining...", nick);
                        fs::remove_file(&file_path)?;
                        HandleClaim::mine(nick.to_string(), &self.identity)
                    }
                }
            }
            false => {
                tracing::info!("Mining new handle claim for '{}'...", nick);
                HandleClaim::mine(nick.to_string(), &self.identity)
            }
        };

        let data =
            rmp_serde::to_vec(&claim).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        fs::create_dir_all(&self.handles_dir)?;
        fs::write(&file_path, data)?;

        tracing::info!("Handle saved to {}", file_path.display());
        Ok(claim)
    }

    pub fn id_server(&self, host: &str, key: &x25519::PublicKey) -> Result<(), PinError> {
        match self.known_servers.get(host) {
            None => Err(PinError::NotKnown),
            Some(pinned_key) => {
                if pinned_key.as_bytes() == key.as_bytes() {
                    Ok(())
                } else {
                    Err(PinError::Mismatch)
                }
            }
        }
    }

    pub fn pin_server(&mut self, host: String, key: x25519::PublicKey) -> io::Result<()> {
        self.known_servers.insert(host, key);
        self.save_pins()
    }
}
