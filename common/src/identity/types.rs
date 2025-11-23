use crate::identity::{Claim, Handle};
use blake2::{Blake2b, digest::consts::U32};
use digest::Digest;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use std::fmt;
use uuid::Uuid;

/// An Identity is an Ed25519 keypair.
///
/// From an Identity, you can:
/// - Mine a Claim for a given nick (proving ownership via VDF)
/// - Derive a UUID from the public key (persistent across servers)
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Create a new random identity.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
        rand::rng().fill_bytes(&mut secret_key_bytes);
        Identity {
            signing_key: SigningKey::from_bytes(&secret_key_bytes),
        }
    }

    /// Load an identity from raw bytes.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Identity {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Export the identity as raw bytes for storage.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Mine a claim for the given nick.
    ///
    /// This performs ~30 seconds of sequential computation.
    /// The result should be cached and reused.
    pub fn mine_claim(&self, nick: &str) -> Claim {
        Claim::mine(nick, &self.signing_key)
    }

    /// Derive a UUID from this identity's public key.
    ///
    /// This UUID is deterministic and persistent across all servers.
    pub fn uuid(&self) -> Uuid {
        let pubkey_bytes = self.verifying_key().to_bytes();
        let hash = Blake2b::<U32>::digest(pubkey_bytes);
        Uuid::from_bytes(hash[0..16].try_into().expect("hash is 32 bytes"))
    }

    /// Get the public key for this identity.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the signing key (private) for this identity.
    ///
    /// Use this carefully - prefer using higher-level methods when possible.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// A public identity verified from a claim.
///
/// Represents a complete authenticated remote user with their persona (handle).
/// Unlike Identity (which has a private key), PublicIdentity only contains:
/// - The public key for signature verification
/// - The verified handle (nick#discriminator)
/// - The persistent UUID
#[derive(Clone, Debug)]
pub struct PublicIdentity {
    verifying_key: VerifyingKey,
    handle: Handle,
    uuid: Uuid,
}

impl PublicIdentity {
    /// Create a public identity from a verified claim.
    ///
    /// This is called internally after claim verification succeeds.
    pub(crate) fn from_verified_claim(verifying_key: VerifyingKey, handle: Handle) -> Self {
        let pubkey_bytes = verifying_key.to_bytes();
        let hash = Blake2b::<U32>::digest(pubkey_bytes);
        let uuid = Uuid::from_bytes(hash[0..16].try_into().expect("hash is 32 bytes"));

        PublicIdentity {
            verifying_key,
            handle,
            uuid,
        }
    }

    /// Get the handle (nick#discriminator) for this user.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Get the persistent UUID for this user.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Get the public key (internal for signature verification).
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.handle, self.uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let identity = Identity::generate();
        let bytes = identity.to_bytes();
        let restored = Identity::from_bytes(&bytes);

        assert_eq!(
            identity.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_uuid_deterministic() {
        let identity = Identity::generate();
        let uuid1 = identity.uuid();
        let uuid2 = identity.uuid();

        assert_eq!(uuid1, uuid2);
    }
}
