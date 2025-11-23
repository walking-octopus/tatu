use crate::identity::ClaimError;

#[derive(Debug, thiserror::Error)]
pub enum ClientHelloError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Claim verification failed: {0}")]
    ClaimVerification(#[from] ClaimError),
}
