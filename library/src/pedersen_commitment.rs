use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;
use std::marker::PhantomData;

/// Pedersen Commitment Scheme
///
/// A Pedersen commitment is a cryptographic commitment scheme that allows one to commit to a value
/// while keeping it hidden, with the ability to reveal the committed value later.
///
/// Properties:
/// - Hiding: The commitment reveals no information about the committed value
/// - Binding: Once committed, the value cannot be changed
/// - Homomorphic: Commitments can be added together
///
/// The commitment is computed as: C = m*G + r*H
/// where:
/// - m is the message (value to commit)
/// - r is a random blinding factor
/// - G and H are generator points on the elliptic curve
pub struct PedersenCommitment<C: CurveGroup> {
    /// First generator point
    pub g: C,
    /// Second generator point (should be independent of g)
    pub h: C,
}

/// Represents a commitment value
#[derive(Clone, Debug, PartialEq)]
pub struct Commitment<C: CurveGroup> {
    pub value: C,
}

/// Opening information needed to verify a commitment
#[derive(Clone, Debug)]
pub struct Opening<F: PrimeField> {
    /// The committed message
    pub message: F,
    /// The random blinding factor
    pub randomness: F,
}

impl<C: CurveGroup> PedersenCommitment<C> {
    /// Create a new Pedersen commitment scheme with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = C::rand(rng);
        let h = C::rand(rng);

        Self { g, h }
    }

    /// Create a new Pedersen commitment scheme with specified generators
    pub fn with_generators(g: C, h: C) -> Self {
        Self { g, h }
    }

    /// Commit to a message with a given randomness
    ///
    /// Computes: C = m*G + r*H
    pub fn commit(&self, message: C::ScalarField, randomness: C::ScalarField) -> Commitment<C> {
        let commitment = self.g * message + self.h * randomness;
        Commitment { value: commitment }
    }

    /// Commit to a message with random blinding factor
    ///
    /// Returns both the commitment and the opening information
    pub fn commit_with_rng<R: Rng>(
        &self,
        message: C::ScalarField,
        rng: &mut R,
    ) -> (Commitment<C>, Opening<C::ScalarField>) {
        let randomness = C::ScalarField::rand(rng);
        let commitment = self.commit(message, randomness);
        let opening = Opening {
            message,
            randomness,
        };
        (commitment, opening)
    }

    /// Verify that a commitment opens to the claimed message
    pub fn verify(&self, commitment: &Commitment<C>, opening: &Opening<C::ScalarField>) -> bool {
        let recomputed = self.commit(opening.message, opening.randomness);
        commitment.value == recomputed.value
    }

    /// Add two commitments (homomorphic property)
    ///
    /// If C1 = m1*G + r1*H and C2 = m2*G + r2*H
    /// Then C1 + C2 = (m1+m2)*G + (r1+r2)*H
    pub fn add_commitments(&self, c1: &Commitment<C>, c2: &Commitment<C>) -> Commitment<C> {
        Commitment {
            value: c1.value + c2.value,
        }
    }

    /// Add two openings (for homomorphic operations)
    pub fn add_openings(
        &self,
        o1: &Opening<C::ScalarField>,
        o2: &Opening<C::ScalarField>,
    ) -> Opening<C::ScalarField> {
        Opening {
            message: o1.message + o2.message,
            randomness: o1.randomness + o2.randomness,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_std::test_rng;

    type TestCurve = G1Projective;
    type ScalarField = Fr;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let message = ScalarField::from(42u64);
        let (commitment, opening) = pc.commit_with_rng(message, &mut rng);

        assert!(pc.verify(&commitment, &opening));
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let message = ScalarField::from(42u64);
        let (commitment, mut opening) = pc.commit_with_rng(message, &mut rng);

        // Change the message
        opening.message = ScalarField::from(43u64);

        assert!(!pc.verify(&commitment, &opening));
    }

    #[test]
    fn test_verify_fails_with_wrong_randomness() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let message = ScalarField::from(42u64);
        let (commitment, mut opening) = pc.commit_with_rng(message, &mut rng);

        // Change the randomness
        opening.randomness = ScalarField::rand(&mut rng);

        assert!(!pc.verify(&commitment, &opening));
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let m1 = ScalarField::from(10u64);
        let m2 = ScalarField::from(20u64);

        let (c1, o1) = pc.commit_with_rng(m1, &mut rng);
        let (c2, o2) = pc.commit_with_rng(m2, &mut rng);

        // Add commitments
        let c_sum = pc.add_commitments(&c1, &c2);
        let o_sum = pc.add_openings(&o1, &o2);

        // Verify that the sum commitment opens to the sum of messages
        assert!(pc.verify(&c_sum, &o_sum));
        assert_eq!(o_sum.message, m1 + m2);
    }

    #[test]
    fn test_commitment_hiding() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let message = ScalarField::from(42u64);

        // Create two commitments to the same message with different randomness
        let (c1, _) = pc.commit_with_rng(message, &mut rng);
        let (c2, _) = pc.commit_with_rng(message, &mut rng);

        // The commitments should be different (hiding property)
        assert_ne!(c1.value, c2.value);
    }

    #[test]
    fn test_commitment_binding() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let m1 = ScalarField::from(42u64);
        let m2 = ScalarField::from(43u64);

        let (commitment, opening) = pc.commit_with_rng(m1, &mut rng);

        // Try to open with a different message
        let fake_opening = Opening {
            message: m2,
            randomness: opening.randomness,
        };

        // Verification should fail (binding property)
        assert!(!pc.verify(&commitment, &fake_opening));
    }

    #[test]
    fn test_zero_commitment() {
        let mut rng = test_rng();
        let pc = PedersenCommitment::<TestCurve>::new(&mut rng);

        let zero = ScalarField::from(0u64);
        let (commitment, opening) = pc.commit_with_rng(zero, &mut rng);

        assert!(pc.verify(&commitment, &opening));
    }
}
