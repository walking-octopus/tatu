use blake2::{Blake2b512, Digest};
use once_cell::sync::Lazy;
use rug::Integer;
use rug::ops::Pow;
use serde::{Deserialize, Serialize};
use thiserror::Error;

static RSA_2048: Lazy<Integer> = Lazy::new(|| {
    Integer::from_str_radix(
    "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
    10
).unwrap()
});

// Difficulty
static T: u32 = i32::pow(2, if cfg!(debug_assertions) { 21 } else { 24 }) as u32;

// FIXME: The .nick handles look suspiciously like base64
// Might be inefficient Integer serde
#[derive(Clone, Serialize, Deserialize)]
pub struct VdfProof {
    pub pi: rug::Integer,
    pub y: rug::Integer,
}

#[derive(Debug, Error)]
pub enum VdfError {
    #[error("VDF proof verification failed")]
    InvalidProof,
}

// Wesolowski, "Efficient verifiable delay functions"
// See https://reading.supply/@whyrusleeping/a-vdf-explainer-5S6Ect

impl VdfProof {
    pub fn mine(seed: &[u8]) -> Self {
        let two_t = Integer::from(2).pow(T);

        let x = hash_group(seed);
        let y = x.clone().pow_mod(&two_t, &RSA_2048).unwrap();

        // powmod isn't constant-time, but there's no secret data involved

        // Fiat–Shamir transform
        let l = hash_prime(&x, &y);
        let (q, _r) = two_t.div_rem(l);
        let pi = x.pow_mod(&q, &RSA_2048).unwrap();

        VdfProof { pi, y }
    }

    pub fn verify(&self, seed: &[u8]) -> Result<(), VdfError> {
        let x = hash_group(seed);
        let l = hash_prime(&x, &self.y);

        let r = (Integer::from(2).pow(T)) % l.clone();

        if self.y
            == &self.pi.clone().pow_mod(&l, &RSA_2048).unwrap() * x.pow_mod(&r, &RSA_2048).unwrap()
                % &*RSA_2048
        {
            Ok(())
        } else {
            Err(VdfError::InvalidProof)
        }
    }
}

fn hash_group(seed: &[u8]) -> Integer {
    let digest: &[u8] = &Blake2b512::digest(seed);
    let x = Integer::from_digits(digest, rug::integer::Order::MsfBe);
    x % (RSA_2048.clone() - 1) + 1
}

fn hash_prime(x: &Integer, y: &Integer) -> Integer {
    let mut h = Blake2b512::new();
    h.update(x.to_digits(rug::integer::Order::MsfBe));
    h.update(y.to_digits(rug::integer::Order::MsfBe));
    let digest = h.finalize();

    let l = Integer::from_digits(&digest, rug::integer::Order::MsfBe);
    l.next_prime()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn proof_uniqueness() {
        let seed1 = b"seed_one";
        let seed2 = b"seed_two";

        let proof1 = VdfProof::mine(seed1);
        let proof2 = VdfProof::mine(seed2);

        assert_ne!(
            proof1.pi, proof2.pi,
            "pi values should be different for different seeds"
        );
        assert_ne!(
            proof1.y, proof2.y,
            "y values should be different for different seeds"
        );
    }

    #[test]
    fn proof_determinism() {
        let seed = b"deterministic_seed";

        let proof1 = VdfProof::mine(seed);
        let proof2 = VdfProof::mine(seed);

        assert_eq!(proof1.pi, proof2.pi, "pi should be deterministic");
        assert_eq!(proof1.y, proof2.y, "y should be deterministic");
    }

    #[test]
    fn roundtrip() {
        let seed = b"test_seed";
        let proof = VdfProof::mine(seed);
        assert!(proof.verify(seed).is_ok(), "Fresh proof should verify");
    }

    #[test]
    fn corrupt_pi() {
        let seed = b"test_seed";
        let mut proof = VdfProof::mine(seed);
        assert!(proof.verify(seed).is_ok(), "Original proof should verify");

        proof.pi ^= Integer::from(123);
        assert!(
            proof.verify(seed).is_err(),
            "Corrupted pi should fail verification"
        );
    }

    #[test]
    fn corrupt_y() {
        let seed = b"test_seed";
        let mut proof = VdfProof::mine(seed);
        assert!(proof.verify(seed).is_ok(), "Original proof should verify");

        proof.y ^= Integer::from(456);
        assert!(
            proof.verify(seed).is_err(),
            "Corrupted y should fail verification"
        );
    }

    #[test]
    fn verify_fast() {
        let seed = b"performance_test";

        let mine_start = Instant::now();
        let proof = VdfProof::mine(seed);
        let mine_duration = mine_start.elapsed();

        let verify_iterations = 100;
        let verify_start = Instant::now();
        for _ in 0..verify_iterations {
            assert!(proof.verify(seed).is_ok());
        }
        let verify_total = verify_start.elapsed();
        let verify_duration = verify_total / verify_iterations;

        println!("Mine time: {:.2}s", mine_duration.as_secs_f64());
        println!(
            "Verify time: {:.2}ms",
            verify_duration.as_secs_f64() * 1000.0
        );
        println!(
            "Speedup: {:.2}x",
            mine_duration.as_secs_f64() / verify_duration.as_secs_f64()
        );

        assert!(
            verify_duration.as_micros() * 1000 < mine_duration.as_micros(),
            "Verification should be at least 1000x faster than mining. Mine: {:?}, Verify: {:?}",
            mine_duration,
            verify_duration
        );
    }
}
