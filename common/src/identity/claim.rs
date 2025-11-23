use crate::primitives::vdf;
use bincode::{Decode, Encode};
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
    #[serde(with = "serde_integer")]
    vdf_output: Integer,
    #[serde(with = "serde_integer")]
    vdf_proof: Integer,
}

mod serde_integer {
    use rug::Integer;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Integer, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = value.to_digits::<u8>(rug::integer::Order::MsfBe);
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Integer, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Integer::from_digits(&bytes, rug::integer::Order::MsfBe))
    }
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

// Manual Encode/Decode for bincode
impl Encode for Claim {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        Encode::encode(&self.nick, encoder)?;
        Encode::encode(&self.nick_signature, encoder)?;
        let vdf_output_bytes = self.vdf_output.to_digits::<u8>(rug::integer::Order::MsfBe);
        let vdf_proof_bytes = self.vdf_proof.to_digits::<u8>(rug::integer::Order::MsfBe);
        Encode::encode(&vdf_output_bytes, encoder)?;
        Encode::encode(&vdf_proof_bytes, encoder)?;
        Ok(())
    }
}

impl<C> Decode<C> for Claim {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let nick = Decode::decode(decoder)?;
        let nick_signature = Decode::decode(decoder)?;
        let vdf_output_bytes: Vec<u8> = Decode::decode(decoder)?;
        let vdf_proof_bytes: Vec<u8> = Decode::decode(decoder)?;

        Ok(Self {
            nick,
            nick_signature,
            vdf_output: Integer::from_digits(&vdf_output_bytes, rug::integer::Order::MsfBe),
            vdf_proof: Integer::from_digits(&vdf_proof_bytes, rug::integer::Order::MsfBe),
        })
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
