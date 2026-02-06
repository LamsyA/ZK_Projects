# Chinese Remainder Theorem (CRT)

## Overview

The **Chinese Remainder Theorem (CRT)** is a fundamental result in number theory that provides a method for solving systems of linear congruences. It states that if you have a system of congruences with pairwise coprime moduli, there exists a unique solution modulo the product of all moduli.

The theorem is named after ancient Chinese mathematical texts and has applications in cryptography, computer science, and number theory.

## Mathematical Explanation

### Problem Statement

Given a system of congruences:

```
x ≡ a₁ (mod m₁)
x ≡ a₂ (mod m₂)
...
x ≡ aₙ (mod mₙ)
```

Where:

- `a₁, a₂, ..., aₙ` are the remainders
- `m₁, m₂, ..., mₙ` are the moduli
- `gcd(mᵢ, mⱼ) = 1` for all `i ≠ j` (pairwise coprime)

### Solution Formula

The unique solution modulo `M = m₁ × m₂ × ... × mₙ` is:

```
x ≡ Σ(aᵢ × Mᵢ × yᵢ) (mod M)
```

Where:

- `M = m₁ × m₂ × ... × mₙ` (product of all moduli)
- `Mᵢ = M / mᵢ` (product of all moduli except mᵢ)
- `yᵢ` is the modular multiplicative inverse of `Mᵢ` modulo `mᵢ`
  - `Mᵢ × yᵢ ≡ 1 (mod mᵢ)`

### Step-by-Step Algorithm

1. **Calculate M**: Multiply all moduli together

   ```
   M = m₁ × m₂ × ... × mₙ
   ```

2. **Calculate Mᵢ for each i**: Divide M by each modulus

   ```
   Mᵢ = M / mᵢ
   ```

3. **Find modular inverses**: For each i, find `yᵢ` such that

   ```
   Mᵢ × yᵢ ≡ 1 (mod mᵢ)
   ```

   Use the Extended Euclidean Algorithm for this step.

4. **Compute the solution**:
   ```
   x = Σ(aᵢ × Mᵢ × yᵢ) mod M
   ```

## Example

Solve the system:

```
x ≡ 2 (mod 3)
x ≡ 3 (mod 5)
x ≡ 2 (mod 7)
```

**Solution:**

1. `M = 3 × 5 × 7 = 105`

2. Calculate Mᵢ values:
   - `M₁ = 105 / 3 = 35`
   - `M₂ = 105 / 5 = 21`
   - `M₃ = 105 / 7 = 15`

3. Find modular inverses:
   - `35 × y₁ ≡ 1 (mod 3)` → `2 × y₁ ≡ 1 (mod 3)` → `y₁ = 2`
   - `21 × y₂ ≡ 1 (mod 5)` → `1 × y₂ ≡ 1 (mod 5)` → `y₂ = 1`
   - `15 × y₃ ≡ 1 (mod 7)` → `1 × y₃ ≡ 1 (mod 7)` → `y₃ = 1`

4. Calculate solution:
   ```
   x = (2 × 35 × 2 + 3 × 21 × 1 + 2 × 15 × 1) mod 105
   x = (140 + 63 + 30) mod 105
   x = 233 mod 105
   x = 23
   ```

**Verification:**

- `23 mod 3 = 2` ✓
- `23 mod 5 = 3` ✓
- `23 mod 7 = 2` ✓

## License

This implementation is provided as educational material.
