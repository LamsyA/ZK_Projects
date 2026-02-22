# RSA (Rivest-Shamir-Adleman) Cryptosystem

## Overview

RSA is an asymmetric (public-key) cryptosystem that enables secure communication and digital signatures. It uses a pair of keys: a public key for encryption and a private key for decryption. RSA is one of the most widely used cryptographic algorithms in the world.

## Historical Context

- **Invented**: 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman
- **Patent**: Expired in 2000
- **Significance**: First practical public-key cryptosystem
- **Applications**: SSL/TLS, email encryption (PGP), digital signatures, blockchain

## Mathematical Foundation

RSA security is based on the difficulty of the **Integer Factorization Problem**: given a large composite number `n = p × q`, it is computationally infeasible to find the prime factors `p` and `q` when they are sufficiently large.

## Key Generation

### Step 1: Choose Two Large Primes

Select two distinct large prime numbers `p` and `q`.

```
Example: p = 61, q = 53
```

### Step 2: Compute the Modulus

Calculate `n = p × q`. This is the modulus used in both public and private keys.

```
n = 61 × 53 = 3233
```

### Step 3: Compute Euler's Totient Function

Calculate `φ(n) = (p - 1) × (q - 1)`. This represents the count of integers less than `n` that are coprime to `n`.

```
φ(n) = (61 - 1) × (53 - 1) = 60 × 52 = 3120
```

### Step 4: Choose the Public Exponent

Select an integer `e` such that:

- `1 < e < φ(n)`
- `gcd(e, φ(n)) = 1` (e and φ(n) must be coprime)

Common choices: `e = 65537` (0x10001) or `e = 3`

```
Example: e = 17
gcd(17, 3120) = 1 ✓
```

### Step 5: Compute the Private Exponent

Calculate `d` such that:

- `(d × e) mod φ(n) = 1`
- `d` is the modular multiplicative inverse of `e` modulo `φ(n)`

```
Example: d = 2753
(2753 × 17) mod 3120 = 46801 mod 3120 = 1 ✓
```

### Key Pair

**Public Key**: `(n, e)` - Can be shared openly

```
(3233, 17)
```

**Private Key**: `(n, d)` - Must be kept secret

```
(3233, 2753)
```

## Encryption

To encrypt a message `m` using the recipient's public key `(n, e)`:

```
c = m^e mod n
```

Where:

- `m` is the plaintext message (as a number)
- `c` is the ciphertext
- `e` is the public exponent
- `n` is the modulus

### Example

```
Message: m = 65
Public key: (n=3233, e=17)

Ciphertext: c = 65^17 mod 3233 = 2790
```

## Decryption

To decrypt a ciphertext `c` using the private key `(n, d)`:

```
m = c^d mod n
```

Where:

- `c` is the ciphertext
- `m` is the recovered plaintext
- `d` is the private exponent
- `n` is the modulus

### Example

```
Ciphertext: c = 2790
Private key: (n=3233, d=2753)

Plaintext: m = 2790^2753 mod 3233 = 65 ✓
```

## Mathematical Verification

The decryption works because of Euler's theorem:

```
c^d mod n = (m^e)^d mod n
          = m^(ed) mod n
          = m^(1 + k×φ(n)) mod n    [since ed ≡ 1 (mod φ(n))]
          = m × (m^φ(n))^k mod n
          = m × 1^k mod n            [by Euler's theorem: m^φ(n) ≡ 1 (mod n)]
          = m mod n
          = m                         [since m < n]
```

## Digital Signatures

RSA can also be used for digital signatures to verify authenticity and non-repudiation.

### Signing

To sign a message `m` with the private key `(n, d)`:

```
signature = m^d mod n
```

### Verification

To verify a signature with the public key `(n, e)`:

```
m = signature^e mod n
```

If the recovered message matches the original, the signature is valid.

## Security Properties

### What is Secure

- The private key `d` is secure
- An attacker sees: `n`, `e`, and ciphertexts
- Computing `d` from `n` and `e` requires factoring `n`, which is computationally hard for large `n`

### What is NOT Secure

- **Textbook RSA**: Deterministic encryption (same plaintext always produces same ciphertext)
  - Solution: Use padding schemes like OAEP (Optimal Asymmetric Encryption Padding)
- **Small Exponents**: If `e` is small and `m^e < n`, the ciphertext is not properly masked
  - Solution: Use proper padding
- **Weak Primes**: If `p` and `q` are not sufficiently random or large
  - Solution: Use cryptographically secure prime generation

## Advantages

1. **Public-Key Cryptography**: Enables secure communication without prior key exchange
2. **Digital Signatures**: Provides authentication and non-repudiation
3. **Widely Standardized**: Supported by most cryptographic libraries
4. **Proven Security**: Security is based on well-understood mathematical problems
5. **Flexible Key Sizes**: Can use 1024, 2048, 4096-bit keys for different security levels

## Disadvantages

1. **Computational Cost**: Much slower than symmetric encryption
2. **Large Key Sizes**: Requires large primes (2048+ bits for modern security)
3. **Padding Required**: Textbook RSA is insecure; proper padding schemes are necessary
4. **Key Management**: Requires secure storage and distribution of public keys
5. **Vulnerable to Quantum Computers**: Shor's algorithm can break RSA in polynomial time

## Practical Considerations

### Key Size Recommendations

- **1024-bit**: Deprecated, no longer considered secure
- **2048-bit**: Minimum for current applications (valid until ~2030)
- **4096-bit**: Recommended for long-term security
- **8192-bit**: Used for highly sensitive applications

### Padding Schemes

- **PKCS#1 v1.5**: Legacy, has vulnerabilities
- **OAEP (Optimal Asymmetric Encryption Padding)**: Recommended, provides semantic security
- **PSS (Probabilistic Signature Scheme)**: For digital signatures

### Performance Optimization

- Use fast modular exponentiation (binary exponentiation)
- Use Chinese Remainder Theorem (CRT) for faster decryption
- Pre-compute values when possible

## Implementation Considerations

1. **Prime Generation**: Use cryptographically secure random number generators
2. **Modular Exponentiation**: Implement efficiently to prevent timing attacks
3. **Padding**: Always use proper padding schemes (OAEP, PSS)
4. **Key Storage**: Protect private keys with encryption and access controls
5. **Certificate Management**: Use X.509 certificates for public key distribution

## Real-World Applications

- **HTTPS/TLS**: Secure web browsing
- **Email Encryption**: PGP, S/MIME
- **Digital Signatures**: Code signing, document signing
- **VPN**: Virtual private networks
- **Blockchain**: Bitcoin, Ethereum address generation
- **SSH**: Secure shell authentication
- **Certificate Authorities**: X.509 certificate signing

## Comparison with Other Algorithms

| Algorithm      | Type         | Key Size       | Speed     | Use Case               |
| -------------- | ------------ | -------------- | --------- | ---------------------- |
| RSA            | Asymmetric   | 2048-4096 bits | Slow      | Encryption, signatures |
| ECC            | Asymmetric   | 256-521 bits   | Faster    | Encryption, signatures |
| AES            | Symmetric    | 128-256 bits   | Very Fast | Bulk encryption        |
| Diffie-Hellman | Key Exchange | 2048+ bits     | Moderate  | Key agreement          |
