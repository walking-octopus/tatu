mod primitives;

pub mod identity;
pub mod protocol;

// Re-export commonly used types
pub use identity::{Claim, ClaimError, Handle, Identity, PublicIdentity};
pub use protocol::{ClientHello, ClientHelloError, ClientResponse, ServerChallenge};
