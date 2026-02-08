# Fermat's Little Theorem (FLT)

## Overview

**Fermat's Little Theorem** is a fundamental result in number theory that provides a powerful tool for modular arithmetic, primality testing, and cryptography. It states that if `p` is a prime number and `a` is an integer not divisible by `p`, then `a` raised to the power of `p-1` is congruent to 1 modulo `p`.

The theorem is named after Pierre de Fermat and has become essential in modern cryptography, particularly in zero-knowledge proofs and RSA encryption.

---

## Mathematical Formula

### The Theorem

For a prime number `p` and an integer `a` where `gcd(a, p) = 1`:

```
a^(p-1) ≡ 1 (mod p)
```

**Where:**

- `a` = any integer not divisible by `p`
- `p` = a prime number
- `≡` = congruent to (modular equivalence)
- `mod p` = modulo `p` (remainder after division by `p`)

### Corollary: Modular Inverse

From Fermat's Little Theorem, we can derive a useful corollary:

```
a^(p-2) ≡ a^(-1) (mod p)
```

This means:

```
a × a^(p-2) ≡ 1 (mod p)
```

Therefore, `a^(p-2)` is the **modular multiplicative inverse** of `a` modulo `p`.

---

## Examples

### Example 1: Basic Verification

**Verify FLT with p=5, a=2:**

```
2^(5-1) mod 5 = 2^4 mod 5
2^4 = 16
16 mod 5 = 1 ✓
```

### Example 2: Another Verification

**Verify FLT with p=7, a=3:**

```
3^(7-1) mod 7 = 3^6 mod 7
3^6 = 729
729 mod 7 = 1 ✓
```

### Example 3: Finding Modular Inverse

**Find the modular inverse of 3 modulo 7:**

Using the corollary: `3^(7-2) mod 7 = 3^5 mod 7`

```
3^5 = 243
243 mod 7 = 5

Verification: 3 × 5 = 15, and 15 mod 7 = 1 ✓
So the modular inverse of 3 modulo 7 is 5
```

---

## Why Fermat's Little Theorem Works

### Mathematical Intuition

Fermat's Little Theorem is based on **Euler's Theorem** and properties of modular arithmetic:

1. **Group Theory Perspective:**
   - The multiplicative group modulo a prime `p` has exactly `p-1` elements
   - By Lagrange's theorem, any element raised to the order of the group equals the identity
   - Therefore: `a^(p-1) ≡ 1 (mod p)`

2. **Combinatorial Proof:**
   - Consider all multiples of `a` modulo `p`: `a, 2a, 3a, ..., (p-1)a`
   - These form a permutation of `1, 2, 3, ..., p-1` (since `p` is prime)
   - Multiplying all elements: `a × 2a × 3a × ... × (p-1)a ≡ 1 × 2 × 3 × ... × (p-1) (mod p)`
   - This simplifies to: `a^(p-1) × (p-1)! ≡ (p-1)! (mod p)`
   - Therefore: `a^(p-1) ≡ 1 (mod p)`

---

## Implementation: Binary Exponentiation

To efficiently compute `a^(p-1) mod p`, we use **Binary Exponentiation** (Exponentiation by Squaring):

### Algorithm Overview

Instead of multiplying `a` by itself `p-1` times (which causes overflow), we:

1. Convert the exponent to binary
2. Process each bit from right to left
3. Square the base at each step
4. Multiply into the result only when the bit is 1
5. Take modulo at each step to keep numbers small

### Time Complexity

- **Naive approach:** O(exponent) - linear time
- **Binary exponentiation:** O(log exponent) - logarithmic time

For `exponent = 1,000,000`:

- Naive: 1,000,000 operations
- Binary: ~20 operations

### Example: Computing 3^4 mod 5

```
exponent = 4 = 100₂ (binary)

Iteration 1:
  Bit = 0 (even), skip multiplication
  base = 3² mod 5 = 4

Iteration 2:
  Bit = 0 (even), skip multiplication
  base = 4² mod 5 = 1

Iteration 3:
  Bit = 1 (odd), multiply
  result = 1 × 1 mod 5 = 1

Result: 1 ✓
```

---

## Applications

### 1. Primality Testing

**Fermat Primality Test:**

To test if `n` is prime:

1. Choose a random integer `a` where `1 < a < n`
2. Compute `a^(n-1) mod n`
3. If result ≠ 1, then `n` is definitely composite
4. If result = 1, then `n` is probably prime

**Advantages:**

- Fast for large numbers
- Probabilistic (can be repeated for higher confidence)

**Disadvantages:**

- Carmichael numbers fool this test
- Use Miller-Rabin test for better reliability

### 2. Modular Inverse Computation

**Finding a^(-1) mod p:**

```
a^(-1) ≡ a^(p-2) (mod p)
```

This is used in:

- Chinese Remainder Theorem (CRT)
- RSA decryption
- Elliptic curve cryptography

### 3. RSA Encryption/Decryption

**RSA relies on FLT:**

- **Public key:** (e, n) where n = p×q (product of two large primes)
- **Private key:** (d, n) where d is computed using FLT properties
- **Encryption:** C ≡ M^e (mod n)
- **Decryption:** M ≡ C^d (mod n)

The security relies on the difficulty of factoring `n` and properties derived from FLT.

---

## Fermat's Little Theorem in Zero-Knowledge Proofs (ZK)

### What are Zero-Knowledge Proofs?

A zero-knowledge proof is a cryptographic protocol where:

- **Prover** proves knowledge of a secret without revealing it
- **Verifier** becomes convinced of the claim
- **Zero-knowledge** means no information about the secret is leaked

### How FLT is Used in ZK

#### 1. **Modular Arithmetic Foundation**

FLT provides the mathematical foundation for modular arithmetic operations in ZK circuits:

```
In ZK proofs, we work in finite fields (mod p where p is prime)
FLT ensures that a^(p-1) ≡ 1 (mod p) for all non-zero elements
This property is used to verify field operations
```

#### 2. **Membership Proofs**

**Proving membership in a set without revealing which element:**

```
Prover knows: secret value 'a' in set S
Prover computes: a^(p-1) mod p = 1
Verifier checks: result = 1
Conclusion: 'a' is a valid field element (non-zero)
```

#### 3. **Range Proofs**

**Proving a value is in a specific range:**

```
Using FLT properties to construct constraints:
- Verify that intermediate values are valid field elements
- Use modular exponentiation to create non-linear constraints
- Prover satisfies all constraints without revealing the value
```

#### 4. **Polynomial Commitments**

**Committing to polynomials in ZK:**

```
Prover commits to polynomial P(x) using:
- Evaluate P at random point r
- Use FLT to verify the evaluation is correct
- Verifier can check commitment without seeing P
```

#### 5. **Schnorr Protocol (Discrete Log Proof)**

**Proving knowledge of discrete logarithm:**

```
Setup:
  g = generator (base)
  p = prime modulus
  h = g^x mod p (public)
  x = secret (what prover knows)

Protocol:
  1. Prover picks random r, computes t = g^r mod p
  2. Prover sends t to verifier
  3. Verifier sends random challenge c
  4. Prover computes z = r + c×x
  5. Verifier checks: g^z ≡ t × h^c (mod p)

This uses FLT to verify the exponentiation is correct!
```

#### 6. **zk-SNARK Circuits**

**In systems like Circom/Arkworks:**

```
Arithmetic circuits work in finite fields (mod p)
FLT ensures:
- Field operations are well-defined
- Modular inverses exist for all non-zero elements
- Exponentiation operations are efficient and correct
```

### Example: Simple ZK Proof Using FLT

**Scenario:** Prover wants to prove they know a secret `s` without revealing it.

```
Setup:
  p = large prime
  g = generator
  h = g^s mod p (public commitment)

Proof:
  1. Prover picks random r
  2. Prover computes t = g^r mod p
  3. Prover sends t to verifier
  4. Verifier sends random challenge c
  5. Prover computes z = r + c×s
  6. Prover sends z to verifier

Verification:
  Verifier checks: g^z ≡ t × h^c (mod p)

  Why this works (using FLT):
  g^z = g^(r + c×s) = g^r × g^(c×s) = t × (g^s)^c = t × h^c ✓

  The verifier is convinced without learning s!
```

---

### Security Considerations in ZK

1. **Soundness:** Prover cannot convince verifier of false statement
   - Relies on difficulty of discrete log problem
   - Requires large prime fields

2. **Zero-Knowledge:** Verifier learns nothing about secret
   - Requires careful protocol design
   - Random challenges must be unpredictable

3. **Completeness:** Honest prover can always convince verifier
   - Guaranteed by FLT properties

---

## Real-World Applications

### 1. **Cryptography**

- RSA encryption/decryption
- Digital signatures
- Key exchange protocols

### 2. **Zero-Knowledge Proofs**

- Schnorr protocol
- zk-SNARKs
- Bulletproofs
- STARKs

### 3. **Blockchain**

- Ethereum smart contracts
- Zero-knowledge rollups
- Privacy-preserving transactions

### 4. **Authentication**

- Challenge-response protocols
- Proof of knowledge
- Identity verification

---

## References

- **Wikipedia:** [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem)
- **Number Theory:** "An Introduction to the Theory of Numbers" by Hardy and Wright
- **Cryptography:** "Handbook of Applied Cryptography" by Menezes, van Oorschot, and Vanstone
- **Zero-Knowledge Proofs:** "The Knowledge Complexity of Interactive Proof Systems" by Goldwasser, Micali, and Rackoff
- **ZK Resources:** [ZK Whiteboard Sessions](https://zk.gnosis.io/)

---

## License

This implementation is provided as educational material for understanding Fermat's Little Theorem and its applications in cryptography and zero-knowledge proofs.
