use crate::primitives::vdf;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use rug::Integer;
use serde::{Deserialize, Serialize};

/// A claim binds a nick to a public key via a VDF proof.
///
/// Claims prove that ~30 seconds of sequential computation was performed,
/// making impersonation attacks economically expensive (2^31 * 30s = ~4000 CPU years).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    nick: String,
    #[serde(with = "serde_big_array::BigArray")]
    nick_signature: [u8; 64],
    vdf_output: Integer,
    vdf_proof: Integer,
}

impl Claim {
    pub fn mine(nick: &str, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;

        let nick_signature = signing_key.sign(nick.as_bytes()).to_bytes();
        let n = vdf::rsa_modulus();
        let seed = [nick.as_bytes(), &nick_signature].concat();
        let x = vdf::hash_to_group(&seed, &n);

        let y = vdf::vdf(&x, vdf::VDF_T, &n);
        let pi = vdf::prove_wesolowski(&x, &y, vdf::VDF_T, &n);

        Claim {
            nick: nick.to_string(),
            nick_signature,
            vdf_output: y,
            vdf_proof: pi,
        }
    }


    /// Verify that this claim is valid for the given public key.
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<(), ClaimError> {
        let signature = Signature::from_bytes(&self.nick_signature);
        pubkey
            .verify(self.nick.as_bytes(), &signature)
            .map_err(|_| ClaimError::InvalidNickSignature)?;

        let n = vdf::rsa_modulus();
        let seed = [self.nick.as_bytes(), &self.nick_signature].concat();
        let x = vdf::hash_to_group(&seed, &n);

        let valid = vdf::verify_wesolowski(&x, &self.vdf_output, &self.vdf_proof, vdf::VDF_T, &n);
        if !valid {
            return Err(ClaimError::InvalidVdfProof);
        }

        Ok(())
    }

    /// Get the handle (nick#discriminator) for this claim.
    pub fn handle(&self) -> crate::identity::Handle {
        crate::identity::Handle::from_nick_and_vdf(&self.nick, &self.vdf_output)
    }

    pub fn nick(&self) -> &str {
        &self.nick
    }

    pub fn nick_signature(&self) -> &[u8; 64] {
        &self.nick_signature
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("Invalid nick signature")]
    InvalidNickSignature,
    #[error("Invalid VDF proof")]
    InvalidVdfProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_mine_and_verify() {
        use crate::Identity;

        let identity = Identity::generate();
        let claim = identity.mine_claim("test");

        // Verification should succeed
        claim.verify(&identity.verifying_key()).unwrap();

        // Handle should be properly formatted
        let handle = claim.handle();
        assert!(handle.as_ref().starts_with("test#"));
        assert_eq!(handle.as_ref().len(), 13); // "test" + "#" + 8 chars
    }

    #[test]
    fn test_claim_verify_wrong_key() {
        use crate::Identity;

        let identity = Identity::generate();
        let wrong_identity = Identity::generate();

        let claim = identity.mine_claim("test");
        let result = claim.verify(&wrong_identity.verifying_key());

        assert!(matches!(result, Err(ClaimError::InvalidNickSignature)));
    }
}
