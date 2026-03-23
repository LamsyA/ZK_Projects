mod aes;
mod diffle_hellman;
mod merkle_tree;
mod pedersen_commitment;
mod rsa;
pub mod univariate;
pub mod multilinear;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::aes;
    use diffle_hellman::diffie_hellman;
    use rsa::rsa;

    #[test]
    fn test_aes() {
        assert!(aes("hello", &[0; 32]));
    }
    #[test]
    fn test_rsa() {
        // Valid RSA parameters: p=61, q=53, e=17, m=65
        // phi = (61-1)*(53-1) = 60*52 = 3120
        // gcd(17, 3120) = 1, so e and phi are coprime
        assert!(rsa(61, 53, 17, 65).is_ok());
    }
    #[test]
    fn test_diffie_hellman() {
        // Standard DH parameters: p=23 (prime), g=5 (generator)
        // Alice's private key: a=6
        // Bob's private key: b=15
        let (alice_pub, bob_pub, shared_secret) = diffie_hellman(23, 5, 6, 15);

        // Verify public keys are computed correctly
        assert_eq!(alice_pub, 8); // 5^6 mod 23 = 8
        assert_eq!(bob_pub, 19); // 5^15 mod 23 = 19

        // Verify shared secret is computed correctly
        assert_eq!(shared_secret, 2); // g^(ab) mod p = 5^90 mod 23 = 2
    }
}
