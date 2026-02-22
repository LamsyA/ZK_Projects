# Diffie-Hellman Key Exchange Protocol

## Overview

The Diffie-Hellman (DH) key exchange is a cryptographic protocol that allows two parties to establish a shared secret over an insecure communication channel without having previously shared any secret information. This shared secret can then be used to encrypt subsequent communications using symmetric encryption.

## Historical Context

- **Invented**: 1976 by Whitfield Diffie and Martin Hellman
- **Significance**: One of the first practical solutions to the key distribution problem
- **Applications**: Used in TLS/SSL, SSH, VPNs, and many other secure communication protocols

## Mathematical Foundation

The protocol relies on the difficulty of the **Discrete Logarithm Problem**: given `g`, `p`, and `g^x mod p`, it is computationally infeasible to find `x` when `p` is a large prime.

### Required Parameters

1. **p** - A large prime number (typically 1024-2048 bits or larger)
2. **g** - A generator (primitive root modulo p), where 1 < g < p

These parameters are public and can be shared openly.

## Protocol Steps

### Setup Phase

Both Alice and Bob agree on public parameters:

- Prime modulus: `p`
- Generator: `g`

### Key Exchange Process

```
Alice                                          Bob
------                                         -----

1. Choose private key: a (secret)      1. Choose private key: b (secret)
   Keep a confidential                    Keep b confidential

2. Compute public key:                 2. Compute public key:
   A = g^a mod p                          B = g^b mod p
   Send A to Bob                          Send B to Alice
   (A is public)                          (B is public)

3. Receive B from Bob                  3. Receive A from Alice

4. Compute shared secret:              4. Compute shared secret:
   s = B^a mod p                          s = A^b mod p
   = (g^b)^a mod p                        = (g^a)^b mod p
   = g^(ab) mod p                         = g^(ab) mod p

5. Both have the same shared secret: s = g^(ab) mod p
```

## Mathematical Verification

Both parties compute the same shared secret due to the properties of modular exponentiation:

```
Alice's computation:  s = B^a mod p = (g^b)^a mod p = g^(ab) mod p
Bob's computation:    s = A^b mod p = (g^a)^b mod p = g^(ab) mod p
```

Since exponentiation is commutative: `(g^b)^a = (g^a)^b = g^(ab)`

## Security Properties

### What is Secure

- The shared secret `s = g^(ab) mod p` is secure
- An eavesdropper sees: `p`, `g`, `A = g^a mod p`, `B = g^b mod p`
- Computing `a` from `A` or `b` from `B` requires solving the discrete logarithm problem, which is computationally hard

### What is NOT Secure

- **Man-in-the-Middle (MITM) Attack**: An attacker can intercept and replace the public keys
  - Attacker intercepts `A` and `B`
  - Attacker sends their own public key to both parties
  - Attacker can compute shared secrets with both Alice and Bob separately
  - Solution: Use digital signatures or certificates to authenticate public keys

## Practical Example

Using small numbers for illustration (in practice, use much larger primes):

```
Public Parameters:
  p = 23 (prime)
  g = 5 (generator)

Alice's Side:
  Private key: a = 6
  Public key: A = 5^6 mod 23 = 15625 mod 23 = 8
  Sends A = 8 to Bob

Bob's Side:
  Private key: b = 15
  Public key: B = 5^15 mod 23 = 30517578125 mod 23 = 19
  Sends B = 19 to Alice

Shared Secret Computation:
  Alice: s = 19^6 mod 23 = 47045881 mod 23 = 2
  Bob:   s = 8^15 mod 23 = 35184372088832 mod 23 = 2

  Both compute s = 2 ✓
```

## Advantages

1. **No Prior Secret Needed**: Parties don't need to have shared a secret beforehand
2. **Public Channel**: Can be performed over an insecure, public channel
3. **Efficient**: Relatively fast computation using modular exponentiation
4. **Widely Adopted**: Standard in many security protocols

## Disadvantages

1. **Vulnerable to MITM**: Without authentication, susceptible to man-in-the-middle attacks
2. **Computational Cost**: Requires large prime numbers and exponentiation operations
3. **No Authentication**: Doesn't verify the identity of the parties
4. **Forward Secrecy**: If private keys are compromised, all past communications can be decrypted

## Variants and Improvements

### Elliptic Curve Diffie-Hellman (ECDH)

- Uses elliptic curve cryptography instead of modular exponentiation
- Provides equivalent security with smaller key sizes
- More efficient for modern applications

### Authenticated Diffie-Hellman

- Combines DH with digital signatures
- Prevents man-in-the-middle attacks
- Used in protocols like TLS

### Perfect Forward Secrecy (PFS)

- Generate new DH parameters for each session
- Even if long-term keys are compromised, past sessions remain secure

## Implementation Considerations

1. **Prime Selection**: Use cryptographically secure primes (Sophie Germain primes)
2. **Generator Verification**: Ensure `g` is a proper generator of the multiplicative group
3. **Key Size**: Use at least 2048-bit primes for modern security
4. **Random Number Generation**: Use cryptographically secure random number generators
5. **Authentication**: Always authenticate the public keys to prevent MITM attacks

## Real-World Applications

- **TLS/SSL**: Secure web browsing (HTTPS)
- **SSH**: Secure shell connections
- **VPN**: Virtual private networks
- **Signal Protocol**: End-to-end encrypted messaging
- **WhatsApp**: Encrypted messaging
- **IPsec**: Internet Protocol Security

## References

- Diffie, W., & Hellman, M. E. (1976). "New directions in cryptography"
- NIST Special Publication 800-56A: Recommendation for Pair-Wise Key Establishment Schemes
- RFC 2631: Diffie-Hellman Key Agreement Method
- RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
