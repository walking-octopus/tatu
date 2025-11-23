use blake2::Blake2s256;
use digest::Digest;
use rug::Integer;
use std::fmt;

/// A full username in the format nick#discriminator (max 16 chars).
///
/// Examples:
/// - alice#xkcd1234 (14 chars)
/// - alexand#dead8337 (16 chars, truncated from "alexander")
///
/// The discriminator is an 8-character string [a-z]{4}[0-9]{4} derived from
/// the VDF output, providing collision resistance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle(String);

impl Handle {
    /// Create a handle from nick and VDF output (internal to identity module).
    pub(crate) fn from_nick_and_vdf(nick: &str, vdf_output: &Integer) -> Self {
        let mut nick = nick.to_string();

        // Truncate nick to ensure total length ≤ 16
        // Format is nick#disc where disc is always 8 chars + 1 for '#' = 9
        // So nick can be at most 7 chars
        if nick.len() > 7 {
            nick.truncate(7);
        }

        // Derive discriminator from VDF output: [a-z]{4}[0-9]{4}
        let y_bytes = vdf_output.to_digits::<u8>(rug::integer::Order::MsfBe);
        let hash = Blake2s256::digest(&y_bytes);
        let hash_u32 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

        let mut discriminator = String::with_capacity(8);
        for i in 0..4 {
            let shift = i * 6;
            let val = ((hash_u32 >> shift) % 26) as u8;
            discriminator.push((b'a' + val) as char);
        }
        for i in 0..4 {
            let shift = i * 4;
            let val = ((hash_u32 >> shift) % 10) as u8;
            discriminator.push((b'0' + val) as char);
        }

        Handle(format!("{}#{}", nick, discriminator))
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_length() {
        let vdf_output = Integer::from(12345u32);
        let handle = Handle::from_nick_and_vdf("alexander", &vdf_output);

        // "alexander" truncated to 7 chars + "#" + 8 char discriminator = 16
        assert_eq!(handle.as_ref().len(), 16);
        assert!(handle.as_ref().starts_with("alexand#"));
    }

    #[test]
    fn test_handle_short_nick() {
        let vdf_output = Integer::from(12345u32);
        let handle = Handle::from_nick_and_vdf("alice", &vdf_output);

        // "alice" (5) + "#" (1) + discriminator (8) = 14
        assert_eq!(handle.as_ref().len(), 14);
        assert!(handle.as_ref().starts_with("alice#"));
    }

    #[test]
    fn test_handle_format() {
        let vdf_output = Integer::from(123456789u64);
        let handle = Handle::from_nick_and_vdf("test", &vdf_output);

        let handle_str = handle.as_ref();
        assert_eq!(handle_str.len(), 13); // "test" + "#" + 8 chars

        // Check format: nick#[a-z]{4}[0-9]{4}
        let parts: Vec<&str> = handle_str.split('#').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "test");
        assert_eq!(parts[1].len(), 8);
        assert!(parts[1].chars().take(4).all(|c| c.is_ascii_lowercase()));
        assert!(parts[1].chars().skip(4).all(|c| c.is_ascii_digit()));
    }
}
