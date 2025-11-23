use blake2::Blake2s256;
use digest::Digest;
use rug::Integer;
use rug::ops::Pow;

pub(crate) fn rsa_modulus() -> Integer {
    Integer::from_str_radix(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
        10,
    )
    .expect("valid RSA-2048 modulus")
}

pub(crate) const VDF_T: u32 = 24;

/// Compute y = x^(2^(2^t)) mod n via 2^t sequential squarings
pub(crate) fn vdf(x: &Integer, t: u32, n: &Integer) -> Integer {
    let iterations = 1u64 << t;
    let mut y = x.clone();
    for _ in 0..iterations {
        y.square_mut();
        y %= n;
    }
    y
}

pub(crate) fn hash_to_group(seed: &[u8], n: &Integer) -> Integer {
    let hash = Blake2s256::digest(seed);
    let hash_int = Integer::from_digits(&hash, rug::integer::Order::MsfBe);
    let n_minus_1 = Integer::from(n - 1);
    (hash_int % n_minus_1) + 1
}

pub(crate) fn hash_to_prime(x: &Integer, y: &Integer) -> Integer {
    for nonce in 0u32..1000 {
        let mut hasher = Blake2s256::new();
        let x_bytes = x.to_digits::<u8>(rug::integer::Order::MsfBe);
        let y_bytes = y.to_digits::<u8>(rug::integer::Order::MsfBe);
        hasher.update(&x_bytes);
        hasher.update(&y_bytes);
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();

        let mut candidate = Integer::from_digits(&hash, rug::integer::Order::MsfBe);
        if candidate.is_even() {
            candidate += 1;
        }

        if candidate.is_probably_prime(20) != rug::integer::IsPrime::No {
            return candidate;
        }
    }

    panic!("Failed to find prime after 1000 attempts");
}

/// Generate Wesolowski proof: π = x^q mod n where q = (2^(2^t) - r) / l
pub(crate) fn prove_wesolowski(x: &Integer, y: &Integer, t: u32, n: &Integer) -> Integer {
    let l = hash_to_prime(x, y);
    let two = Integer::from(2);
    let big_t = Integer::from(1) << t;
    let r = two.pow_mod(&big_t, &l).expect("modpow failed");

    let big_t_u32 = big_t.to_u32().expect("t too large");
    let two_to_big_t = Integer::from(2).pow(big_t_u32);
    let q = (two_to_big_t - &r) / &l;

    Integer::from(x.pow_mod_ref(&q, n).unwrap())
}

pub(crate) fn verify_wesolowski(x: &Integer, y: &Integer, pi: &Integer, t: u32, n: &Integer) -> bool {
    let l = hash_to_prime(x, y);
    let two = Integer::from(2);
    let big_t = Integer::from(1) << t;
    let r = two.pow_mod(&big_t, &l).expect("modpow failed");

    let pi_to_l = Integer::from(pi.pow_mod_ref(&l, n).unwrap());
    let x_to_r = Integer::from(x.pow_mod_ref(&r, n).unwrap());
    let lhs = (pi_to_l * x_to_r) % n;

    &lhs == y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_prime() {
        let x = Integer::from(12345);
        let y = Integer::from(67890);
        let p = hash_to_prime(&x, &y);

        assert_eq!(p, hash_to_prime(&x, &y));
        assert!(p.is_odd());
    }

    #[test]
    fn test_vdf_small() {
        let n = rsa_modulus();
        let x = Integer::from(1234);
        let t = 10;

        let y = vdf(&x, t, &n);
        let pi = prove_wesolowski(&x, &y, t, &n);
        let valid = verify_wesolowski(&x, &y, &pi, t, &n);

        assert!(valid);
    }

    #[test]
    fn test_vdf_larger() {
        let n = rsa_modulus();
        let x = Integer::from(5678);
        let t = 15;

        let y = vdf(&x, t, &n);
        let pi = prove_wesolowski(&x, &y, t, &n);
        let valid = verify_wesolowski(&x, &y, &pi, t, &n);

        assert!(valid);
    }
}
