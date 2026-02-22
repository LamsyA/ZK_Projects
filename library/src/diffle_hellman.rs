/// Diffie-Hellman Key Exchange Implementation
///
/// The Diffie-Hellman protocol allows two parties to establish a shared secret
/// over an insecure channel without prior communication.

/// Modular exponentiation using binary exponentiation
/// Computes (base^exponent) mod modulus efficiently
use crate::rsa::mod_exp;

/// Represents a party in the Diffie-Hellman key exchange
pub struct DHParty {
    /// Prime modulus (p)
    pub p: i128,
    /// Generator (g)
    pub g: i128,
    /// Private key (a or b)
    pub private_key: i128,
    /// Public key (A or B)
    pub public_key: i128,
}

impl DHParty {
    /// Creates a new Diffie-Hellman party with given parameters
    ///
    /// # Arguments
    /// * `p` - A large prime number
    /// * `g` - A generator (primitive root modulo p)
    /// * `private_key` - A random private key (should be kept secret)
    ///
    /// # Returns
    /// A new DHParty with computed public key
    pub fn new(p: i128, g: i128, private_key: i128) -> Self {
        let public_key = mod_exp(g, private_key, p);
        DHParty {
            p,
            g,
            private_key,
            public_key,
        }
    }

    /// Computes the shared secret given the other party's public key
    ///
    /// # Arguments
    /// * `other_public_key` - The public key of the other party
    ///
    /// # Returns
    /// The shared secret (same for both parties)
    pub fn compute_shared_secret(&self, other_public_key: i128) -> i128 {
        mod_exp(other_public_key, self.private_key, self.p)
    }
}

/// Simplified Diffie-Hellman key exchange function
///
/// # Arguments
/// * `p` - Prime modulus
/// * `g` - Generator
/// * `a` - Alice's private key
/// * `b` - Bob's private key
///
/// # Returns
/// A tuple containing (Alice's public key, Bob's public key, shared secret)
pub fn diffie_hellman(p: i128, g: i128, a: i128, b: i128) -> (i128, i128, i128) {
    // Alice computes her public key: A = g^a mod p
    let alice_public = mod_exp(g, a, p);

    // Bob computes his public key: B = g^b mod p
    let bob_public = mod_exp(g, b, p);

    // Alice computes shared secret: s = B^a mod p
    let alice_shared = mod_exp(bob_public, a, p);

    // Bob computes shared secret: s = A^b mod p
    // Both should be equal: s = g^(ab) mod p
    let bob_shared = mod_exp(alice_public, b, p);

    // Verify they match (they should in a correct implementation)
    assert_eq!(alice_shared, bob_shared, "Shared secrets do not match!");

    (alice_public, bob_public, alice_shared)
}
