use ark_ff::Field;

use std::fmt;
use std::ops::{Add, Mul, Sub};

/// A multilinear polynomial represented in sparse form using a Vec.
///
/// A multilinear polynomial has degree at most 1 in each variable.
/// For n variables, it has the form:
/// P(x₁, x₂, ..., xₙ) = Σ c_S * ∏(i∈S) xᵢ
/// where S ⊆ {1, 2, ..., n} and c_S are field elements.
///
/// **Sparse Representation:**
/// - Only stores non-zero coefficients as (bitmask, coefficient) pairs
/// - Bitmask encodes which variables appear in each monomial
/// - Memory efficient: O(k) where k = number of non-zero terms
/// - Ideal for ZK proofs with many variables but sparse polynomials
///
/// **Field Arithmetic:**
/// - Only works with finite fields (arkworks Field trait)
/// - No floating-point arithmetic allowed
/// - All operations are exact field arithmetic
/// - Optimized for prime field arithmetic used in ZK applications
///
/// # Example
/// ```ignore
/// use ark_bn254::Fr;
/// use library::MultilinearPolynomial;
///
/// // Create P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
/// let mut poly = MultilinearPolynomial::<Fr>::new(2);
/// poly.set_coefficient(0, Fr::from(3u32));  // constant term
/// poly.set_coefficient(1, Fr::from(2u32));  // x0 coefficient
/// poly.set_coefficient(2, Fr::from(5u32));  // x1 coefficient
/// poly.set_coefficient(3, Fr::from(7u32));  // x0*x1 coefficient
///
/// // Evaluate at point (1, 1)
/// let result = poly.evaluate(&[Fr::from(1u32), Fr::from(1u32)]);
/// // result = 3 + 2*1 + 5*1 + 7*1*1 = 17
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilinearPolynomial<F: Field> {
    /// Number of variables
    num_vars: usize,
    /// Sparse representation: Vec of (bitmask, coefficient) tuples, sorted by bitmask
    /// - Bitmask: bit i set means variable x_i appears in the monomial
    /// - Coefficient: field element coefficient for that monomial
    terms: Vec<(u64, F)>,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Creates a new zero polynomial with specified number of variables.
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables in the polynomial
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // Create a zero polynomial with 3 variables
    /// let poly = MultilinearPolynomial::<Fr>::new(3);
    /// assert_eq!(poly.num_vars(), 3);
    /// assert!(poly.is_zero());
    /// ```
    pub fn new(num_vars: usize) -> Self {
        MultilinearPolynomial {
            num_vars,
            terms: Vec::new(),
        }
    }

    /// Creates a multilinear polynomial from a vector of (bitmask, coefficient) tuples.
    ///
    /// Automatically removes zero coefficients, validates bitmasks, and sorts terms.
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables
    /// * `terms` - Vec of (bitmask, coefficient) tuples
    ///
    /// # Bitmask Encoding
    /// - Bit 0 set → x0 appears in monomial
    /// - Bit 1 set → x1 appears in monomial
    /// - Bit i set → xi appears in monomial
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // Create P(x0, x1) = 3 + 2*x0 + 5*x1
    /// let terms = vec![
    ///     (0b00, Fr::from(3u32)),  // constant: 3
    ///     (0b01, Fr::from(2u32)),  // x0: 2*x0
    ///     (0b10, Fr::from(5u32)),  // x1: 5*x1
    /// ];
    /// let poly = MultilinearPolynomial::from_terms(2, terms);
    /// ```
    pub fn from_terms(num_vars: usize, mut terms: Vec<(u64, F)>) -> Self {
        // Remove zero coefficients
        terms.retain(|(_, coeff)| !coeff.is_zero());

        // Validate bitmasks don't exceed num_vars
        let max_mask = (1u64 << num_vars) - 1;
        terms.retain(|(mask, _)| *mask <= max_mask);

        // Sort by bitmask
        terms.sort_by_key(|(mask, _)| *mask);

        // Remove duplicates by summing coefficients with same mask
        let mut deduplicated: Vec<(u64, F)> = Vec::new();
        for (mask, coeff) in terms {
            if let Some((last_mask, last_coeff)) = deduplicated.last_mut() {
                if *last_mask == mask {
                    *last_coeff += coeff;
                    if last_coeff.is_zero() {
                        deduplicated.pop();
                    }
                    continue;
                }
            }
            deduplicated.push((mask, coeff));
        }

        MultilinearPolynomial {
            num_vars,
            terms: deduplicated,
        }
    }

    /// Sets the coefficient for a specific monomial.
    ///
    /// # Arguments
    /// * `mask` - Bitmask indicating which variables are in the monomial
    /// * `coeff` - Coefficient value (zero removes the term)
    ///
    /// # Returns
    /// Result indicating success or error if bitmask exceeds number of variables
    ///
    /// # Example
    /// ```ignore
    ///
    /// let mut poly = MultilinearPolynomial::<Fr>::new(2);
    /// poly.set_coefficient(0, Fr::from(3u32))?;  // constant = 3
    /// poly.set_coefficient(1, Fr::from(2u32))?;  // x0 coeff = 2
    /// poly.set_coefficient(3, Fr::from(7u32))?;  // x0*x1 coeff = 7
    /// // Now poly = 3 + 2*x0 + 7*x0*x1
    /// ```
    pub fn set_coefficient(&mut self, mask: u64, coeff: F) -> Result<(), String> {
        if mask >= (1u64 << self.num_vars) {
            return Err(format!(
                "Bitmask {} exceeds maximum for {} variables",
                mask, self.num_vars
            ));
        }

        // Find if mask already exists
        if let Some(pos) = self.terms.iter().position(|(m, _)| *m == mask) {
            if coeff.is_zero() {
                self.terms.remove(pos);
            } else {
                self.terms[pos].1 = coeff;
            }
        } else if !coeff.is_zero() {
            // Insert in sorted order
            let pos = self
                .terms
                .binary_search_by_key(&mask, |(m, _)| *m)
                .unwrap_or_else(|e| e);
            self.terms.insert(pos, (mask, coeff));
        }
        Ok(())
    }

    /// Gets the coefficient for a specific monomial.
    ///
    /// Returns zero if the term doesn't exist.
    ///
    /// # Arguments
    /// * `mask` - Bitmask indicating which variables are in the monomial
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// let mut poly = MultilinearPolynomial::<Fr>::new(2);
    /// poly.set_coefficient(1, Fr::from(5u32));
    ///
    /// assert_eq!(poly.get_coefficient(1), Fr::from(5u32));  // x0 coefficient
    /// assert_eq!(poly.get_coefficient(2), Fr::zero());       // x1 coefficient (not set)
    /// ```
    pub fn get_coefficient(&self, mask: u64) -> F {
        self.terms
            .binary_search_by_key(&mask, |(m, _)| *m)
            .ok()
            .map(|idx| self.terms[idx].1)
            .unwrap_or_else(F::zero)
    }

    /// Returns the number of variables.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Returns the number of non-zero terms.
    pub fn num_terms(&self) -> usize {
        self.terms.len()
    }

    /// Checks if the polynomial is zero.
    pub fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }

    /// Returns an iterator over the terms (mask, coefficient).
    pub fn iter(&self) -> impl Iterator<Item = (u64, &F)> {
        self.terms.iter().map(|(m, c)| (*m, c))
    }

    /// Returns a reference to the internal terms vec.
    pub fn terms(&self) -> &Vec<(u64, F)> {
        &self.terms
    }

    /// Evaluates the polynomial at a given point using Boolean Hypercube method.
    ///
    /// This is the primary evaluation method. It iteratively fixes variables
    /// one at a time, reducing the polynomial dimension until reaching a scalar.
    ///
    /// **Algorithm:**
    /// 1. Start with the full polynomial
    /// 2. For each variable i, fix it to point[i] using partial evaluation
    /// 3. Continue until all variables are fixed
    /// 4. Return the final scalar value
    ///
    /// **Complexity:** O(k * n) where k = number of terms, n = number of variables
    ///
    /// # Arguments
    /// * `point` - Vector of field elements, one for each variable
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
    /// let mut poly = MultilinearPolynomial::<Fr>::new(2);
    /// poly.set_coefficient(0, Fr::from(3u32));
    /// poly.set_coefficient(1, Fr::from(2u32));
    /// poly.set_coefficient(2, Fr::from(5u32));
    /// poly.set_coefficient(3, Fr::from(7u32));
    ///
    /// // Evaluate at (1, 1)
    /// let result = poly.evaluate(&[Fr::from(1u32), Fr::from(1u32)]);
    /// // result = 3 + 2*1 + 5*1 + 7*1*1 = 17
    /// assert_eq!(result, Fr::from(17u32));
    /// ```
    pub fn evaluate(&self, point: &[F]) -> Result<F, String> {
        if point.len() != self.num_vars {
            //
            return Err(format!("Point dimension must match number of variables"));
        }

        // Use Boolean Hypercube method for evaluation
        let mut current_poly = self.clone();

        // Iteratively fix each variable
        for i in 0..self.num_vars {
            current_poly = current_poly.partial_evaluate(0, point[i]);
        }

        // After all variables are fixed, we have a 0-variable polynomial (constant)
        if current_poly.num_vars() == 0 && current_poly.num_terms() == 1 {
            Ok(current_poly.get_coefficient(0))
        } else if current_poly.num_vars() == 0 && current_poly.num_terms() == 0 {
            Ok(F::zero())
        } else {
            Err(format!("Unexpected State"))
        }
    }

    /// Partially evaluates the polynomial by fixing one variable.
    ///
    /// This is the core operation for Boolean Hypercube evaluation.
    /// It fixes variable at `var_index` to `value` and returns a new polynomial
    /// with one fewer variable.
    ///
    /// **Algorithm:**
    /// 1. For each term, check if the variable appears
    /// 2. If yes: multiply coefficient by value and remove variable from mask
    /// 3. If no: keep term as-is
    /// 4. Combine terms with same mask
    /// 5. Shift bitmasks to account for removed variable
    ///
    /// # Arguments
    /// * `var_index` - Index of variable to fix (0-indexed)
    /// * `value` - Value to assign to the variable
    ///
    /// # Returns
    /// A new polynomial with `num_vars - 1` variables
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
    /// let mut poly = MultilinearPolynomial::<Fr>::new(2);
    /// poly.set_coefficient(0, Fr::from(1u32));
    /// poly.set_coefficient(1, Fr::from(2u32));
    /// poly.set_coefficient(2, Fr::from(3u32));
    /// poly.set_coefficient(3, Fr::from(4u32));
    ///
    /// // Fix x0 = 1: Q(x1) = 1 + 2*1 + 3*x1 + 4*1*x1 = 3 + 7*x1
    /// let partial = poly.partial_evaluate(0, Fr::from(1u32));
    /// assert_eq!(partial.num_vars(), 1);
    /// assert_eq!(partial.get_coefficient(0), Fr::from(3u32));  // constant
    /// assert_eq!(partial.get_coefficient(1), Fr::from(7u32));  // x1 coefficient
    /// ```
    pub fn partial_evaluate(&self, var_index: usize, value: F) -> MultilinearPolynomial<F> {
        if var_index >= self.num_vars {
            panic!("Variable index out of bounds");
        }

        let var_mask = 1u64 << var_index;
        let mut new_terms: Vec<(u64, F)> = Vec::new();

        for (mask, coeff) in self.iter() {
            if (mask & var_mask) != 0 {
                // Variable is in this monomial, multiply by value
                let new_mask = mask & !var_mask;
                let new_coeff = *coeff * value;

                // Find or insert the new_mask
                if let Some(pos) = new_terms
                    .iter()
                    .position(|(m, _): &(u64, F)| *m == new_mask)
                {
                    new_terms[pos].1 += new_coeff;
                    if new_terms[pos].1.is_zero() {
                        new_terms.remove(pos);
                    }
                } else {
                    new_terms.push((new_mask, new_coeff));
                }
            } else {
                // Variable is not in this monomial, keep as is
                if let Some(pos) = new_terms.iter().position(|(m, _): &(u64, F)| *m == mask) {
                    new_terms[pos].1 += coeff;
                    if new_terms[pos].1.is_zero() {
                        new_terms.remove(pos);
                    }
                } else {
                    new_terms.push((mask, *coeff));
                }
            }
        }

        // Sort the new terms
        new_terms.sort_by_key(|(m, _)| *m);

        // Shift bitmasks: move all bits after var_index down by 1
        let mut shifted_terms: Vec<(u64, F)> = Vec::new();
        for (mask, coeff) in new_terms {
            // Split mask into lower and upper parts
            let lower_mask = mask & ((1u64 << var_index) - 1); // bits below var_index
            let upper_mask = (mask >> (var_index + 1)) << var_index; // bits above var_index, shifted down
            let shifted_mask = lower_mask | upper_mask;
            shifted_terms.push((shifted_mask, coeff));
        }

        MultilinearPolynomial {
            num_vars: self.num_vars - 1,
            terms: shifted_terms,
        }
    }

    /// Reconstructs a multilinear polynomial from evaluations at all Boolean hypercube points.
    ///
    /// Given evaluations at all 2^n points in {0,1}^n, reconstructs the unique
    /// multilinear polynomial using the Möbius transform.
    ///
    /// **Möbius Transform Algorithm:**
    /// For each variable i (0 to n-1):
    ///   For each bitmask where bit i is set:
    ///     coeffs[mask] -= coeffs[mask without bit i]
    ///
    /// This extracts the contribution of each variable subset.
    ///
    /// **Sparse Conversion:**
    /// After computing all 2^n coefficients, only non-zero ones are stored,
    /// maintaining the sparse representation.
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables
    /// * `evaluations` - Vector of 2^num_vars evaluations at Boolean hypercube points
    ///   - Index 0: P(0,0,...,0)
    ///   - Index 1: P(1,0,...,0)
    ///   - Index 2: P(0,1,...,0)
    ///   - etc.
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // Evaluations at {0,1}^2: P(0,0)=1, P(1,0)=3, P(0,1)=4, P(1,1)=10
    /// let evaluations = vec![
    ///     Fr::from(1u32),   // P(0,0)
    ///     Fr::from(3u32),   // P(1,0)
    ///     Fr::from(4u32),   // P(0,1)
    ///     Fr::from(10u32),  // P(1,1)
    /// ];
    ///
    /// // Reconstruct polynomial
    /// let poly = MultilinearPolynomial::from_evaluations(2, evaluations);
    /// // Result: P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
    /// ```
    ///
    /// # Detailed Example
    /// ```text
    /// Consider P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
    ///
    /// Evaluations at {0,1}^2:
    ///   - P(0,0) = 3
    ///   - P(1,0) = 3 + 2 = 5
    ///   - P(0,1) = 3 + 5 = 8
    ///   - P(1,1) = 3 + 2 + 5 + 7 = 17
    ///
    /// Möbius Transform:
    ///   - Start: [3, 5, 8, 17]
    ///   - After var 0: [3, 5-3=2, 8, 17-8=9]
    ///   - After var 1: [3, 2, 8-3=5, 9-2=7]
    ///   - Result: [3, 2, 5, 7] → coefficients for 1, x0, x1, x0*x1
    ///
    /// Sparse representation:
    ///   - Vec: [(0, 3), (1, 2), (2, 5), (3, 7)]
    ///   - Bitmask 0 (0b00) → constant term 3
    ///   - Bitmask 1 (0b01) → x0 coefficient 2
    ///   - Bitmask 2 (0b10) → x1 coefficient 5
    ///   - Bitmask 3 (0b11) → x0*x1 coefficient 7
    /// ```
    pub fn from_evaluations(num_vars: usize, evaluations: Vec<F>) -> Self {
        if evaluations.len() != (1 << num_vars) {
            panic!("Number of evaluations must be 2^num_vars");
        }

        let mut poly = MultilinearPolynomial::new(num_vars);

        // Use Möbius transform to convert evaluations to coefficients
        let mut coeffs = evaluations.clone();

        // Apply Möbius transform: iteratively extract variable contributions
        for i in 0..num_vars {
            for mask in 0..(1u64 << num_vars) {
                if (mask & (1u64 << i)) != 0 {
                    let prev_mask = mask ^ (1u64 << i);
                    let prev_val = coeffs[prev_mask as usize];
                    coeffs[mask as usize] -= prev_val;
                }
            }
        }

        // Set non-zero coefficients (sparse representation)
        for (mask, coeff) in coeffs.iter().enumerate() {
            if !coeff.is_zero() {
                poly.set_coefficient(mask as u64, *coeff);
            }
        }

        poly
    }

    /// Returns intermediate polynomials during Boolean Hypercube evaluation.
    ///
    /// This method is essential for the Sumcheck protocol, where the verifier
    /// needs to see the polynomial at each round after fixing variables.
    ///
    /// **Algorithm:**
    /// 1. Start with the original polynomial
    /// 2. For each variable i, fix it to point[i]
    /// 3. Store the resulting polynomial
    /// 4. Continue until all variables are fixed
    ///
    /// # Arguments
    /// * `point` - Vector of field elements, one for each variable
    ///
    /// # Returns
    /// A vector of polynomials where:
    /// - `result[0]` = original polynomial (n variables)
    /// - `result[1]` = after fixing first variable (n-1 variables)
    /// - `result[2]` = after fixing first two variables (n-2 variables)
    /// - ...
    /// - `result[n]` = final constant (0 variables)
    ///
    /// # Example
    /// ```ignore
    /// use ark_bn254::Fr;
    /// use library::MultilinearPolynomial;
    ///
    /// // P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
    /// let mut poly = MultilinearPolynomial::<Fr>::new(2);
    /// poly.set_coefficient(0, Fr::from(3u32));
    /// poly.set_coefficient(1, Fr::from(2u32));
    /// poly.set_coefficient(2, Fr::from(5u32));
    /// poly.set_coefficient(3, Fr::from(7u32));
    ///
    /// // Get intermediates when evaluating at (1, 1)
    /// let intermediates = poly.evaluate_with_intermediates(&[Fr::from(1u32), Fr::from(1u32)]);
    ///
    /// // intermediates[0] = P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
    /// assert_eq!(intermediates[0].num_vars(), 2);
    ///
    /// // intermediates[1] = P(1, x1) = 5 + 12*x1
    /// assert_eq!(intermediates[1].num_vars(), 1);
    /// assert_eq!(intermediates[1].get_coefficient(0), Fr::from(5u32));
    /// assert_eq!(intermediates[1].get_coefficient(1), Fr::from(12u32));
    ///
    /// // intermediates[2] = P(1, 1) = 17
    /// assert_eq!(intermediates[2].num_vars(), 0);
    /// assert_eq!(intermediates[2].get_coefficient(0), Fr::from(17u32));
    /// ```
    ///
    /// # Sumcheck Protocol Usage
    /// ```text
    /// In Sumcheck protocol:
    /// - Prover sends univariate polynomial for each round
    /// - Verifier checks consistency and sends random challenge
    /// - This method provides the polynomial state at each round
    /// - Essential for computing the next round's univariate polynomial
    /// ```
    pub fn evaluate_with_intermediates(&self, point: &[F]) -> Vec<MultilinearPolynomial<F>> {
        if point.len() != self.num_vars {
            panic!("Point dimension must match number of variables");
        }

        let mut intermediates = vec![self.clone()];
        let mut current_poly = self.clone();

        // Iteratively fix each variable
        for i in 0..self.num_vars {
            current_poly = current_poly.partial_evaluate(0, point[i]);
            intermediates.push(current_poly.clone());
        }

        intermediates
    }

    /// Converts bitmask to variable indices.
    ///
    /// Helper function for display and debugging.
    ///
    /// # Example
    /// ```text
    /// mask = 0b101 (5) → [0, 2] → represents x0*x2
    /// mask = 0b011 (3) → [0, 1] → represents x0*x1
    /// ```
    fn mask_to_vars(mask: u64) -> Vec<usize> {
        let mut vars = Vec::new();
        let mut m = mask;
        let mut i = 0;
        while m > 0 {
            if (m & 1) != 0 {
                vars.push(i);
            }
            m >>= 1;
            i += 1;
        }
        vars
    }
}

impl<F: Field> Default for MultilinearPolynomial<F> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<F: Field + fmt::Display> fmt::Display for MultilinearPolynomial<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        let mut first = true;
        for (mask, coeff) in self.terms.iter().rev() {
            if !first {
                write!(f, " + ")?;
            }
            first = false;

            let vars = Self::mask_to_vars(*mask);
            if vars.is_empty() {
                write!(f, "{}", coeff)?;
            } else {
                write!(f, "{}", coeff)?;
                for var in vars {
                    write!(f, "*x{}", var)?;
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Arithmetic Operations (Field-based, ZK-safe)
// ============================================================================

impl<F: Field> Add for MultilinearPolynomial<F> {
    type Output = Self;

    /// Adds two multilinear polynomials.
    ///
    /// # Example
    /// ```ignore
    /// // P(x0) = 1 + 2*x0
    /// // Q(x0) = 3 + 4*x0
    /// // P + Q = 4 + 6*x0
    /// let result = p1 + p2;
    /// ```
    fn add(self, other: Self) -> Self {
        if self.num_vars != other.num_vars {
            panic!("Polynomials must have same number of variables");
        }

        let mut result = self.terms.clone();

        for (mask, coeff) in other.iter() {
            if let Some(pos) = result.iter().position(|(m, _)| *m == mask) {
                result[pos].1 += coeff;
                if result[pos].1.is_zero() {
                    result.remove(pos);
                }
            } else {
                result.push((mask, *coeff));
            }
        }

        // Sort the result
        result.sort_by_key(|(m, _)| *m);

        MultilinearPolynomial {
            num_vars: self.num_vars,
            terms: result,
        }
    }
}

impl<F: Field> Sub for MultilinearPolynomial<F> {
    type Output = Self;

    /// Subtracts two multilinear polynomials.
    ///
    /// # Example
    /// ```ignore
    /// // P(x0) = 5 + 3*x0
    /// // Q(x0) = 2 + 1*x0
    /// // P - Q = 3 + 2*x0
    /// let result = p1 - p2;
    /// ```
    fn sub(self, other: Self) -> Self {
        if self.num_vars != other.num_vars {
            panic!("Polynomials must have same number of variables");
        }

        let mut result = self.terms.clone();

        for (mask, coeff) in other.iter() {
            if let Some(pos) = result.iter().position(|(m, _)| *m == mask) {
                result[pos].1 -= coeff;
                if result[pos].1.is_zero() {
                    result.remove(pos);
                }
            } else {
                result.push((mask, -*coeff));
            }
        }

        // Sort the result
        result.sort_by_key(|(m, _)| *m);

        MultilinearPolynomial {
            num_vars: self.num_vars,
            terms: result,
        }
    }
}

impl<F: Field> Mul for MultilinearPolynomial<F> {
    type Output = Self;

    /// Multiplies two multilinear polynomials using XOR for monomial combination.
    ///
    /// In multilinear polynomials, xi * xi = xi (idempotent), which is
    /// implemented via XOR of bitmasks: mask1 XOR mask2.
    ///
    /// # Example
    /// ```ignore
    /// // P(x0) = 1 + x0
    /// // Q(x0) = 1 + x0
    /// // P * Q = (1 + x0)^2
    /// //       = 1*1 + 1*x0 + x0*1 + x0*x0
    /// //       = 1 + x0 + x0 + 1  (since x0*x0 = 1 via XOR)
    /// //       = 2 + 2*x0
    /// let result = p1 * p2;
    /// ```
    fn mul(self, other: Self) -> Self {
        if self.num_vars != other.num_vars {
            panic!("Polynomials must have same number of variables");
        }

        if self.is_zero() || other.is_zero() {
            return MultilinearPolynomial::new(self.num_vars);
        }

        let mut result_map: Vec<(u64, F)> = Vec::new();

        for (mask1, coeff1) in self.iter() {
            for (mask2, coeff2) in other.iter() {
                // XOR masks to combine monomials (multilinear property)
                let new_mask = mask1 ^ mask2;
                let new_coeff = *coeff1 * coeff2;

                if let Some(pos) = result_map.iter().position(|(m, _)| *m == new_mask) {
                    result_map[pos].1 += new_coeff;
                    if result_map[pos].1.is_zero() {
                        result_map.remove(pos);
                    }
                } else {
                    result_map.push((new_mask, new_coeff));
                }
            }
        }

        // Sort by mask
        result_map.sort_by_key(|(m, _)| *m);

        MultilinearPolynomial {
            num_vars: self.num_vars,
            terms: result_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::Zero;

    #[test]
    fn test_creation() {
        let poly = MultilinearPolynomial::<Fr>::new(3);
        assert_eq!(poly.num_vars(), 3);
        assert!(poly.is_zero());
        assert_eq!(poly.num_terms(), 0);
    }

    #[test]
    fn test_set_and_get_coefficient() {
        let mut poly = MultilinearPolynomial::<Fr>::new(3);

        // Set constant term (mask = 0)
        poly.set_coefficient(0, Fr::from(5u32));
        assert_eq!(poly.get_coefficient(0), Fr::from(5u32));

        // Set x0 term (mask = 1)
        poly.set_coefficient(1, Fr::from(2u32));
        assert_eq!(poly.get_coefficient(1), Fr::from(2u32));

        // Set x0*x1 term (mask = 3 = 0b11)
        poly.set_coefficient(3, Fr::from(3u32));
        assert_eq!(poly.get_coefficient(3), Fr::from(3u32));

        assert_eq!(poly.num_terms(), 3);
    }

    #[test]
    fn test_addition() {
        let mut p1 = MultilinearPolynomial::<Fr>::new(2);
        p1.set_coefficient(0, Fr::from(1u32)); // constant
        p1.set_coefficient(1, Fr::from(2u32)); // x0

        let mut p2 = MultilinearPolynomial::<Fr>::new(2);
        p2.set_coefficient(0, Fr::from(3u32)); // constant
        p2.set_coefficient(2, Fr::from(4u32)); // x1

        let result = p1 + p2;
        assert_eq!(result.get_coefficient(0), Fr::from(4u32)); // 1 + 3
        assert_eq!(result.get_coefficient(1), Fr::from(2u32)); // 2
        assert_eq!(result.get_coefficient(2), Fr::from(4u32)); // 4
    }

    #[test]
    fn test_subtraction() {
        let mut p1 = MultilinearPolynomial::<Fr>::new(2);
        p1.set_coefficient(0, Fr::from(5u32));
        p1.set_coefficient(1, Fr::from(3u32));

        let mut p2 = MultilinearPolynomial::<Fr>::new(2);
        p2.set_coefficient(0, Fr::from(2u32));
        p2.set_coefficient(1, Fr::from(1u32));

        let result = p1 - p2;
        assert_eq!(result.get_coefficient(0), Fr::from(3u32)); // 5 - 2
        assert_eq!(result.get_coefficient(1), Fr::from(2u32)); // 3 - 1
    }

    #[test]
    fn test_evaluation_basic() {
        // P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32)); // constant
        poly.set_coefficient(1, Fr::from(2u32)); // x0
        poly.set_coefficient(2, Fr::from(3u32)); // x1
        poly.set_coefficient(3, Fr::from(4u32)); // x0*x1

        // Evaluate at (0, 0)
        let point = vec![Fr::from(0u32), Fr::from(0u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(1u32)));

        // Evaluate at (1, 0)
        let point = vec![Fr::from(1u32), Fr::from(0u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(3u32))); // 1 + 2

        // Evaluate at (0, 1)
        let point = vec![Fr::from(0u32), Fr::from(1u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(4u32))); // 1 + 3

        // Evaluate at (1, 1)
        let point = vec![Fr::from(1u32), Fr::from(1u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(10u32))); // 1 + 2 + 3 + 4
    }

    #[test]
    fn test_partial_evaluation() {
        // P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(2, Fr::from(3u32));
        poly.set_coefficient(3, Fr::from(4u32));

        // Fix x0 = 1: P(1, x1) = 1 + 2 + 3*x1 + 4*x1 = 3 + 7*x1
        let partial = poly.partial_evaluate(0, Fr::from(1u32));
        assert_eq!(partial.num_vars(), 1);
        assert_eq!(partial.get_coefficient(0), Fr::from(3u32)); // constant
        assert_eq!(partial.get_coefficient(1), Fr::from(7u32)); // x1 coefficient
    }

    #[test]
    fn test_from_evaluations() {
        // Create polynomial from evaluations at all points in {0,1}^2
        // P(0,0) = 1, P(1,0) = 3, P(0,1) = 4, P(1,1) = 10
        let evaluations = vec![
            Fr::from(1u32),
            Fr::from(3u32),
            Fr::from(4u32),
            Fr::from(10u32),
        ];

        let poly = MultilinearPolynomial::from_evaluations(2, evaluations);

        // Verify by evaluating at all points
        assert_eq!(
            poly.evaluate(&vec![Fr::from(0u32), Fr::from(0u32)]),
            Ok(Fr::from(1u32))
        );
        assert_eq!(
            poly.evaluate(&vec![Fr::from(1u32), Fr::from(0u32)]),
            Ok(Fr::from(3u32))
        );
        assert_eq!(
            poly.evaluate(&vec![Fr::from(0u32), Fr::from(1u32)]),
            Ok(Fr::from(4u32))
        );
        assert_eq!(
            poly.evaluate(&vec![Fr::from(1u32), Fr::from(1u32)]),
            Ok(Fr::from(10u32))
        );
    }

    #[test]
    fn test_multiplication() {
        // P(x0) = 1 + x0
        let mut p1 = MultilinearPolynomial::<Fr>::new(1);
        p1.set_coefficient(0, Fr::from(1u32));
        p1.set_coefficient(1, Fr::from(1u32));

        // Q(x0) = 1 + x0
        let mut p2 = MultilinearPolynomial::<Fr>::new(1);
        p2.set_coefficient(0, Fr::from(1u32));
        p2.set_coefficient(1, Fr::from(1u32));

        // P * Q = (1 + x0) * (1 + x0)
        // Using XOR for multilinear multiplication:
        // = 1*1 (mask 0 XOR 0 = 0) + 1*x0 (mask 0 XOR 1 = 1) + x0*1 (mask 1 XOR 0 = 1) + x0*x0 (mask 1 XOR 1 = 0)
        // = 1 + x0 + x0 + 1 = 2 + 2*x0
        let result = p1 * p2;
        assert_eq!(result.get_coefficient(0), Fr::from(2u32));
        assert_eq!(result.get_coefficient(1), Fr::from(2u32));
    }

    #[test]
    fn test_sparse_representation() {
        // Create sparse polynomial with many variables but few terms
        let mut poly = MultilinearPolynomial::<Fr>::new(20);
        poly.set_coefficient(0, Fr::from(1u32)); // constant
        poly.set_coefficient(1 << 5, Fr::from(2u32)); // x5
        poly.set_coefficient((1 << 10) | (1 << 15), Fr::from(3u32)); // x10*x15

        assert_eq!(poly.num_vars(), 20);
        assert_eq!(poly.num_terms(), 3);
    }

    #[test]
    fn test_zero_coefficient_removal() {
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(5u32));
        poly.set_coefficient(1, Fr::from(3u32));

        // Setting to zero should remove
        poly.set_coefficient(1, Fr::zero());
        assert_eq!(poly.num_terms(), 1);
        assert_eq!(poly.get_coefficient(1), Fr::zero());
    }

    #[test]
    fn test_three_variable_polynomial() {
        // P(x0, x1, x2) = 1 + x0 + x1 + x2 + x0*x1 + x0*x2 + x1*x2 + x0*x1*x2
        let mut poly = MultilinearPolynomial::<Fr>::new(3);
        for mask in 0..8 {
            poly.set_coefficient(mask, Fr::from(1u32));
        }

        // Evaluate at (1, 1, 1)
        let point = vec![Fr::from(1u32), Fr::from(1u32), Fr::from(1u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(8u32)));

        // Evaluate at (0, 0, 0)
        let point = vec![Fr::from(0u32), Fr::from(0u32), Fr::from(0u32)];
        assert_eq!(poly.evaluate(&point), Ok(Fr::from(1u32)));
    }

    // ========================================================================
    // Boolean Hypercube Evaluation Tests
    // ========================================================================

    #[test]
    fn test_evaluation_2vars() {
        // P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(3u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(2, Fr::from(5u32));
        poly.set_coefficient(3, Fr::from(7u32));

        // Evaluate at (1, 1)
        let point = vec![Fr::from(1u32), Fr::from(1u32)];
        let result = poly.evaluate(&point);

        // Expected: 3 + 2*1 + 5*1 + 7*1*1 = 17
        assert_eq!(result, Ok(Fr::from(17u32)));
    }

    #[test]
    fn test_evaluation_3vars() {
        // P(x0, x1, x2) = 1 + x0 + x1 + x2 + x0*x1 + x0*x2 + x1*x2 + x0*x1*x2
        let mut poly = MultilinearPolynomial::<Fr>::new(3);
        for mask in 0..8 {
            poly.set_coefficient(mask, Fr::from(1u32));
        }

        // Evaluate at (1, 1, 1)
        let point = vec![Fr::from(1u32), Fr::from(1u32), Fr::from(1u32)];
        let result = poly.evaluate(&point);

        // Expected: 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = 8
        assert_eq!(result, Ok(Fr::from(8u32)));
    }

    #[test]
    fn test_evaluation_zero_point() {
        // P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(3u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(2, Fr::from(5u32));
        poly.set_coefficient(3, Fr::from(7u32));

        // Evaluate at (0, 0)
        let point = vec![Fr::from(0u32), Fr::from(0u32)];
        let result = poly.evaluate(&point);

        // Expected: 3 (only constant term)
        assert_eq!(result, Ok(Fr::from(3u32)));
    }

    #[test]
    fn test_with_intermediates() {
        // P(x0, x1) = 3 + 2*x0 + 5*x1 + 7*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(3u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(2, Fr::from(5u32));
        poly.set_coefficient(3, Fr::from(7u32));

        let point = vec![Fr::from(1u32), Fr::from(1u32)];
        let intermediates = poly.evaluate_with_intermediates(&point);

        // Should have 3 polynomials: original, after fixing x0, after fixing x1
        assert_eq!(intermediates.len(), 3);

        // First should be the original (2 variables)
        assert_eq!(intermediates[0].num_vars(), 2);
        assert_eq!(intermediates[0].num_terms(), 4);

        // Second should have 1 variable (after fixing x0 = 1)
        assert_eq!(intermediates[1].num_vars(), 1);

        // Third should have 0 variables (constant)
        assert_eq!(intermediates[2].num_vars(), 0);
        assert_eq!(intermediates[2].num_terms(), 1);

        // Final value should be 17
        assert_eq!(intermediates[2].get_coefficient(0), Fr::from(17u32));
    }

    #[test]
    fn test_sumcheck_protocol_simulation() {
        // Simulate Sumcheck protocol step
        // P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(2, Fr::from(3u32));
        poly.set_coefficient(3, Fr::from(4u32));

        // Prover's random challenge
        let challenge = vec![Fr::from(5u32), Fr::from(7u32)];

        // Get intermediate polynomials
        let intermediates = poly.evaluate_with_intermediates(&challenge);

        // Verify structure for Sumcheck
        assert_eq!(intermediates.len(), 3); // n + 1 polynomials

        // Each intermediate should have one fewer variable
        for i in 0..intermediates.len() {
            assert_eq!(intermediates[i].num_vars(), 2 - i);
        }

        // Final result should match direct evaluation
        let direct = poly.evaluate(&challenge);
        let final_value = intermediates[2].get_coefficient(0);
        assert_eq!(direct, Ok(final_value));
    }

    #[test]
    fn test_single_variable() {
        // P(x0) = 5 + 3*x0
        let mut poly = MultilinearPolynomial::<Fr>::new(1);
        poly.set_coefficient(0, Fr::from(5u32));
        poly.set_coefficient(1, Fr::from(3u32));

        // Evaluate at x0 = 2
        let point = vec![Fr::from(2u32)];
        let result = poly.evaluate(&point);

        // Expected: 5 + 3*2 = 11
        assert_eq!(result, Ok(Fr::from(11u32)));
    }

    #[test]
    fn test_sparse_polynomial_evaluation() {
        // Sparse polynomial with many variables but few terms
        let mut poly = MultilinearPolynomial::<Fr>::new(5);
        poly.set_coefficient(0, Fr::from(10u32)); // constant
        poly.set_coefficient(1 << 2, Fr::from(4u32)); // x2
        poly.set_coefficient((1 << 3) | (1 << 4), Fr::from(6u32)); // x3*x4

        let point = vec![
            Fr::from(1u32),
            Fr::from(2u32),
            Fr::from(3u32),
            Fr::from(4u32),
            Fr::from(5u32),
        ];

        let result = poly.evaluate(&point);

        // Expected: 10 + 4*3 + 6*4*5 = 10 + 12 + 120 = 142
        assert_eq!(result, Ok(Fr::from(142u32)));
    }

    #[test]
    fn test_from_terms() {
        // Create polynomial using from_terms
        let terms = vec![
            (0, Fr::from(3u32)),
            (1, Fr::from(2u32)),
            (2, Fr::from(5u32)),
            (3, Fr::from(7u32)),
        ];
        let poly = MultilinearPolynomial::from_terms(2, terms);

        // Verify coefficients
        assert_eq!(poly.get_coefficient(0), Fr::from(3u32));
        assert_eq!(poly.get_coefficient(1), Fr::from(2u32));
        assert_eq!(poly.get_coefficient(2), Fr::from(5u32));
        assert_eq!(poly.get_coefficient(3), Fr::from(7u32));
    }
}
