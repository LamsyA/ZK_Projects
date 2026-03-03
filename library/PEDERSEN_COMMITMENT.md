# Pedersen Commitment Scheme

A complete implementation of the Pedersen commitment scheme using the arkworks library.

## Overview

The Pedersen commitment scheme is a cryptographic commitment scheme that allows one to commit to a value while keeping it hidden, with the ability to reveal the committed value later. It's widely used in zero-knowledge proofs and privacy-preserving protocols.

## Mathematical Foundation

A Pedersen commitment is computed as:

```
C = m*G + r*H
```

Where:

- `m` is the message (value to commit)
- `r` is a random blinding factor
- `G` and `H` are generator points on an elliptic curve
- `C` is the resulting commitment

## Properties

### 1. **Hiding**

The commitment reveals no information about the committed value. Even with unlimited computational power, an adversary cannot determine the message from the commitment alone (information-theoretically secure).

### 2. **Binding**

Once committed, the value cannot be changed. It's computationally infeasible to find two different openings (m, r) and (m', r') that produce the same commitment (assuming the discrete logarithm problem is hard).

### 3. **Homomorphic**

Commitments can be added together:

```
C1 + C2 = (m1*G + r1*H) + (m2*G + r2*H) = (m1+m2)*G + (r1+r2)*H
```

This property is useful for building more complex cryptographic protocols.

## Implementation Details

### Core Components

1. **PedersenCommitment<C>**: The main struct that holds the generator points
2. **Commitment<C>**: Represents a commitment value
3. **Opening<F>**: Contains the message and randomness needed to verify a commitment

### Key Methods

- `new(rng)`: Create a new commitment scheme with random generators
- `with_generators(g, h)`: Create a scheme with specific generators
- `commit(message, randomness)`: Create a commitment with given parameters
- `commit_with_rng(message, rng)`: Create a commitment with random blinding factor
- `verify(commitment, opening)`: Verify that a commitment opens correctly
- `add_commitments(c1, c2)`: Add two commitments (homomorphic property)
- `add_openings(o1, o2)`: Add two openings

## Usage Examples

### Basic Commitment and Verification

```rust
use library::pedersen_commitment::{PedersenCommitment, Commitment, Opening};
use ark_bn254::{G1Projective, Fr};
use ark_std::test_rng;

fn main() {
    let mut rng = test_rng();

    // Create a new Pedersen commitment scheme
    let pc = PedersenCommitment::<G1Projective>::new(&mut rng);

    // Commit to a value
    let message = Fr::from(42u64);
    let (commitment, opening) = pc.commit_with_rng(message, &mut rng);

    // Verify the commitment
    assert!(pc.verify(&commitment, &opening));
    println!("Commitment verified successfully!");
}
```

### Homomorphic Addition

```rust
use library::pedersen_commitment::PedersenCommitment;
use ark_bn254::{G1Projective, Fr};
use ark_std::test_rng;

fn main() {
    let mut rng = test_rng();
    let pc = PedersenCommitment::<G1Projective>::new(&mut rng);

    // Commit to two values
    let m1 = Fr::from(10u64);
    let m2 = Fr::from(20u64);

    let (c1, o1) = pc.commit_with_rng(m1, &mut rng);
    let (c2, o2) = pc.commit_with_rng(m2, &mut rng);

    // Add the commitments
    let c_sum = pc.add_commitments(&c1, &c2);
    let o_sum = pc.add_openings(&o1, &o2);

    // Verify that the sum commitment opens to the sum of messages
    assert!(pc.verify(&c_sum, &o_sum));
    assert_eq!(o_sum.message, m1 + m2);

    println!("Homomorphic addition verified!");
}
```

### Custom Generators

```rust
use library::pedersen_commitment::PedersenCommitment;
use ark_bn254::{G1Projective, Fr};
use ark_ec::CurveGroup;
use ark_std::test_rng;
use ark_ff::UniformRand;

fn main() {
    let mut rng = test_rng();

    // Generate custom generator points
    let g = G1Projective::rand(&mut rng);
    let h = G1Projective::rand(&mut rng);

    // Create commitment scheme with custom generators
    let pc = PedersenCommitment::with_generators(g, h);

    let message = Fr::from(100u64);
    let (commitment, opening) = pc.commit_with_rng(message, &mut rng);

    assert!(pc.verify(&commitment, &opening));
}
```

## Security Considerations

1. **Generator Independence**: The generators G and H must be chosen such that no one knows the discrete logarithm relationship between them. If someone knows `x` such that `H = x*G`, they can break the binding property.

2. **Randomness Quality**: The blinding factor `r` must be chosen uniformly at random from a cryptographically secure random number generator. Reusing randomness or using predictable randomness breaks the hiding property.

3. **Discrete Logarithm Assumption**: The security of the binding property relies on the hardness of the discrete logarithm problem in the chosen elliptic curve group.

## Use Cases

1. **Zero-Knowledge Proofs**: Pedersen commitments are fundamental building blocks in many ZK proof systems
2. **Confidential Transactions**: Used in cryptocurrencies to hide transaction amounts while still allowing verification
3. **Verifiable Secret Sharing**: Commitments to shares in secret sharing schemes
4. **Voting Systems**: Commit to votes before revealing them
5. **Auctions**: Sealed-bid auctions where bids are committed before revelation

## Testing

The implementation includes comprehensive tests covering:

- Basic commitment and verification
- Verification failure with wrong message
- Verification failure with wrong randomness
- Homomorphic addition
- Hiding property
- Binding property
- Zero commitments

Run tests with:

```bash
cargo test pedersen_commitment
```

## Dependencies

- `ark-ec`: Elliptic curve operations
- `ark-ff`: Finite field arithmetic
- `ark-std`: Standard utilities for arkworks
- `ark-bn254`: BN254 curve implementation (used in tests)
- `rand`: Random number generation

## References

1. [Pedersen, T. P. (1991). "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"](https://reaction.la/security/pedersons_secret_sharing.pdf)
2. [arkworks documentation](https://docs.rs/ark-ec/)
3. [Pedersen Commitment on Wikipedia](https://en.wikipedia.org/wiki/Commitment_scheme#Pedersen_commitment)
