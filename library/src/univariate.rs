use ark_ff::Field;
use std::fmt;
use std::ops::{Add, Mul, Sub};

/// A univariate polynomial represented in sparse form using a Vec.
/// Stores only non-zero coefficients as (degree, coefficient) tuples.
/// Tuples are kept sorted by degree for efficient operations.
///
/// **IMPORTANT**: This implementation is strictly for Zero-Knowledge Proofs.
/// - Only works with finite fields (arkworks Field trait)
/// - No floating-point arithmetic allowed
/// - All operations are exact field arithmetic
/// - Optimized for prime field arithmetic used in ZK applications
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnivariatePolynomial<F: Field> {
    /// Vector of (degree, coefficient) tuples, sorted by degree
    /// Only non-zero coefficients are stored
    terms: Vec<(usize, F)>,
}

impl<F: Field> UnivariatePolynomial<F> {
    /// Creates a new empty polynomial (zero polynomial).
    pub fn new() -> Self {
        UnivariatePolynomial { terms: Vec::new() }
    }

    /// Creates a polynomial from a vector of (degree, coefficient) tuples.
    /// Automatically removes zero coefficients and sorts by degree.
    ///
    /// # Arguments
    /// * `terms` - Vector of (degree, coefficient) tuples
    ///
    /// # Returns
    /// A UnivariatePolynomial with deduplicated and sorted terms
    pub fn from_terms(mut terms: Vec<(usize, F)>) -> Self {
        // Remove zero coefficients
        terms.retain(|(_, coeff)| !coeff.is_zero());
        // Sort by degree
        terms.sort_by_key(|(degree, _)| *degree);
        // Remove duplicates by summing coefficients with same degree
        let mut deduplicated: Vec<(usize, F)> = Vec::new();
        for (degree, coeff) in terms {
            if let Some((last_degree, last_coeff)) = deduplicated.last_mut() {
                if *last_degree == degree {
                    *last_coeff += coeff;
                    if last_coeff.is_zero() {
                        deduplicated.pop();
                    }
                    continue;
                }
            }
            deduplicated.push((degree, coeff));
        }
        UnivariatePolynomial {
            terms: deduplicated,
        }
    }

    /// Sets the coefficient for a given degree.
    /// If the coefficient is zero, it removes the entry.
    ///
    /// # Arguments
    /// * `degree` - The degree of the term
    /// * `coeff` - The coefficient (must be a field element)
    pub fn set_coefficient(&mut self, degree: usize, coeff: F) {
        // Find if degree already exists
        if let Some(pos) = self.terms.iter().position(|(d, _)| *d == degree) {
            if coeff.is_zero() {
                self.terms.remove(pos);
            } else {
                self.terms[pos].1 = coeff;
            }
        } else if !coeff.is_zero() {
            // Insert in sorted order
            let pos = self
                .terms
                .binary_search_by_key(&degree, |(d, _)| *d)
                .unwrap_or_else(|e| e);
            self.terms.insert(pos, (degree, coeff));
        }
    }

    /// Gets the coefficient for a given degree.
    /// Returns zero if the degree is not present.
    ///
    /// # Arguments
    /// * `degree` - The degree to query
    ///
    /// # Returns
    /// The coefficient at that degree, or F::zero() if not present
    pub fn get_coefficient(&self, degree: usize) -> F {
        self.terms
            .binary_search_by_key(&degree, |(d, _)| *d)
            .ok()
            .map(|idx| self.terms[idx].1)
            .unwrap_or_else(F::zero)
    }

    /// Returns the degree of the polynomial.
    /// Returns 0 for the zero polynomial.
    pub fn degree(&self) -> usize {
        self.terms.last().map(|(degree, _)| *degree).unwrap_or(0)
    }

    /// Returns the number of non-zero terms in the polynomial.
    pub fn num_terms(&self) -> usize {
        self.terms.len()
    }

    /// Returns an iterator over the terms (degree, coefficient) in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &F)> {
        self.terms.iter().map(|(d, c)| (*d, c))
    }

    /// Returns a mutable iterator over the terms.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut F)> {
        self.terms.iter_mut().map(|(d, c)| (*d, c))
    }

    /// Checks if the polynomial is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }

    /// Returns a reference to the internal Vec of terms.
    pub fn terms(&self) -> &Vec<(usize, F)> {
        &self.terms
    }

    /// Evaluates the polynomial at a given point using Horner's method.
    /// This is the most efficient method for field arithmetic.
    ///
    /// Horner's method: P(x) = (...((a_n * x + a_{n-1}) * x + a_{n-2}) * x + ... + a_1) * x + a_0
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate (a field element)
    ///
    /// # Returns
    /// The value of the polynomial at x (a field element)
    pub fn evaluate_horner(&self, x: F) -> F {
        if self.is_zero() {
            return F::zero();
        }

        let degree = self.degree();
        let mut result = F::zero();

        for d in (0..=degree).rev() {
            result = result * x + self.get_coefficient(d);
        }

        result
    }

    /// Evaluates the polynomial at a given point using direct substitution.
    /// Less efficient than Horner's method but useful for verification.
    ///
    /// Direct: P(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate (a field element)
    ///
    /// # Returns
    /// The value of the polynomial at x (a field element)
    pub fn evaluate_direct(&self, x: F) -> F {
        let mut result = F::zero();

        for (degree, coeff) in self.iter() {
            let mut x_power = F::one();
            for _ in 0..degree {
                x_power *= x;
            }
            result += *coeff * x_power;
        }

        result
    }

    /// Returns the number of field multiplications needed for Horner evaluation.
    /// Useful for complexity analysis in ZK circuits.
    pub fn horner_complexity(&self) -> usize {
        self.degree()
    }

    /// Returns the number of field multiplications needed for direct evaluation.
    pub fn direct_complexity(&self) -> usize {
        self.terms.iter().map(|(d, _)| d).sum()
    }
}

impl<F: Field> Default for UnivariatePolynomial<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field + fmt::Display> fmt::Display for UnivariatePolynomial<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        let mut first = true;
        // Iterate in reverse by collecting and reversing
        for (degree, coeff) in self.terms.iter().rev() {
            if !first {
                write!(f, " + ")?;
            }
            first = false;

            if *degree == 0 {
                write!(f, "{}", coeff)?;
            } else if *degree == 1 {
                write!(f, "{}x", coeff)?;
            } else {
                write!(f, "{}x^{}", coeff, degree)?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// Arithmetic Operations for Field Elements (ZK-safe)
// ============================================================================

impl<F: Field> Add for UnivariatePolynomial<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Vec::new();
        let mut i = 0;
        let mut j = 0;

        while i < self.terms.len() && j < other.terms.len() {
            let (deg1, coeff1) = self.terms[i];
            let (deg2, coeff2) = other.terms[j];

            if deg1 < deg2 {
                result.push((deg1, coeff1));
                i += 1;
            } else if deg1 > deg2 {
                result.push((deg2, coeff2));
                j += 1;
            } else {
                // Same degree, add coefficients
                let sum = coeff1 + coeff2;
                if !sum.is_zero() {
                    result.push((deg1, sum));
                }
                i += 1;
                j += 1;
            }
        }

        // Add remaining terms
        while i < self.terms.len() {
            result.push(self.terms[i]);
            i += 1;
        }
        while j < other.terms.len() {
            result.push(other.terms[j]);
            j += 1;
        }

        UnivariatePolynomial { terms: result }
    }
}

impl<F: Field> Sub for UnivariatePolynomial<F> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut result = Vec::new();
        let mut i = 0;
        let mut j = 0;

        while i < self.terms.len() && j < other.terms.len() {
            let (deg1, coeff1) = self.terms[i];
            let (deg2, coeff2) = other.terms[j];

            if deg1 < deg2 {
                result.push((deg1, coeff1));
                i += 1;
            } else if deg1 > deg2 {
                result.push((deg2, -coeff2));
                j += 1;
            } else {
                // Same degree, subtract coefficients
                let diff = coeff1 - coeff2;
                if !diff.is_zero() {
                    result.push((deg1, diff));
                }
                i += 1;
                j += 1;
            }
        }

        // Add remaining terms
        while i < self.terms.len() {
            result.push(self.terms[i]);
            i += 1;
        }
        while j < other.terms.len() {
            result.push((other.terms[j].0, -other.terms[j].1));
            j += 1;
        }

        UnivariatePolynomial { terms: result }
    }
}

impl<F: Field> Mul for UnivariatePolynomial<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return UnivariatePolynomial::new();
        }

        let mut result_map: Vec<(usize, F)> = Vec::new();

        for (deg1, coeff1) in self.iter() {
            for (deg2, coeff2) in other.iter() {
                let new_degree = deg1 + deg2;
                let new_coeff = *coeff1 * coeff2;

                // Find or insert the degree
                if let Some(pos) = result_map.iter().position(|(d, _)| *d == new_degree) {
                    result_map[pos].1 += new_coeff;
                    if result_map[pos].1.is_zero() {
                        result_map.remove(pos);
                    }
                } else {
                    result_map.push((new_degree, new_coeff));
                }
            }
        }

        // Sort by degree
        result_map.sort_by_key(|(degree, _)| *degree);

        UnivariatePolynomial { terms: result_map }
    }
}

// ============================================================================
// Lagrange Interpolation for Finite Fields (ZK-safe)
// ============================================================================

/// Performs Lagrange interpolation on a set of points over a finite field.
/// Returns a polynomial that passes through all given points.
///
/// **IMPORTANT FOR ZK**: This uses only finite field arithmetic.
/// - All operations are exact (no floating-point approximation)
/// - Uses field inversion for denominator
/// - Suitable for Shamir's Secret Sharing and polynomial commitments
///
/// # Arguments
/// * `points` - A slice of (x, y) tuples representing the points to interpolate
///              Both x and y must be field elements
///
/// # Returns
/// A UnivariatePolynomial that passes through all the given points
///
/// # Panics
/// Panics if any two x-coordinates are equal (duplicate points)
pub fn lagrange_interpolation<F: Field>(points: &[(F, F)]) -> UnivariatePolynomial<F> {
    if points.is_empty() {
        return UnivariatePolynomial::new();
    }

    let n = points.len();
    let mut result = UnivariatePolynomial::new();

    for i in 0..n {
        let (xi, yi) = points[i];

        // Compute the Lagrange basis polynomial L_i(x)
        let mut basis = UnivariatePolynomial::new();
        basis.set_coefficient(0, F::one()); // Start with 1

        for j in 0..n {
            if i != j {
                let (xj, _) = points[j];
                let denominator = xi - xj;

                // Field inversion - this is exact arithmetic in finite fields
                let denominator_inv = denominator
                    .inverse()
                    .expect("Denominator must be non-zero (duplicate x-coordinates not allowed)");

                // Multiply basis by (x - xj) / (xi - xj)
                let mut factor = UnivariatePolynomial::new();
                factor.set_coefficient(1, denominator_inv); // Coefficient of x
                factor.set_coefficient(0, -xj * denominator_inv); // Constant term

                basis = basis * factor;
            }
        }

        // Multiply by yi and add to result
        for (degree, coeff) in basis.iter() {
            let current = result.get_coefficient(degree);
            result.set_coefficient(degree, current + yi * coeff);
        }
    }

    result
}

// ============================================================================
// Boolean Hypercube for Multilinear Polynomial Evaluation (ZK-safe)
// ============================================================================

/// A Boolean Hypercube represents the domain {0, 1}^n for n variables.
/// Used in multilinear polynomial evaluation and ZK proof systems.
///
/// **IMPORTANT FOR ZK**:
/// - Represents all 2^n boolean assignments for n variables
/// - Uses sparse representation: only stores non-zero evaluations
/// - Each point is indexed by a bitmask (0 to 2^n - 1)
/// - Efficient for sumcheck protocols and polynomial commitments
/// - Integrates with multilinear polynomial evaluation
///
/// **Sparse Representation:**
/// - Only stores non-zero evaluations as (index, value) pairs
/// - Index corresponds to boolean assignment (bitmask)
/// - Memory efficient: O(k) where k = number of non-zero evaluations
/// - Ideal for sparse evaluation tables in ZK proofs
///
/// # Example
/// For n=2, the hypercube contains 4 points:
/// - Index 0 (0b00): (0, 0)
/// - Index 1 (0b01): (1, 0)
/// - Index 2 (0b10): (0, 1)
/// - Index 3 (0b11): (1, 1)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BooleanHypercube<F: Field> {
    /// Number of variables (dimension)
    num_vars: usize,
    /// Sparse representation: Vec of (index, value) tuples, sorted by index
    /// Index is the bitmask representing the boolean assignment
    /// Only non-zero evaluations are stored
    evaluations: Vec<(u64, F)>,
}

impl<F: Field> BooleanHypercube<F> {
    /// Creates a new empty Boolean hypercube for n variables.
    /// No evaluations are stored initially (sparse representation).
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables (dimension of hypercube)
    ///
    /// # Returns
    /// A BooleanHypercube with no evaluations
    pub fn new(num_vars: usize) -> Self {
        BooleanHypercube {
            num_vars,
            evaluations: Vec::new(),
        }
    }

    /// Creates a Boolean hypercube from evaluations at all 2^n points.
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables
    /// * `evaluations` - Vector of 2^num_vars evaluations
    ///   - Index i corresponds to the boolean assignment represented by bitmask i
    ///   - Only non-zero values are stored (sparse representation)
    ///
    /// # Example
    /// ```ignore
    /// // Evaluations at {0,1}^2: f(0,0)=1, f(1,0)=0, f(0,1)=2, f(1,1)=0
    /// let evals = vec![Fr::from(1u32), Fr::zero(), Fr::from(2u32), Fr::zero()];
    /// let hypercube = BooleanHypercube::from_evaluations(2, evals);
    /// // Stores only: [(0, 1), (2, 2)]
    /// ```
    pub fn from_evaluations(num_vars: usize, evaluations: Vec<F>) -> Self {
        if evaluations.len() != (1 << num_vars) {
            panic!("Number of evaluations must be 2^num_vars");
        }

        let mut sparse_evals = Vec::new();
        for (index, value) in evaluations.iter().enumerate() {
            if !value.is_zero() {
                sparse_evals.push((index as u64, *value));
            }
        }

        BooleanHypercube {
            num_vars,
            evaluations: sparse_evals,
        }
    }

    /// Returns the number of variables (dimension).
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Returns the total number of points in the hypercube (2^num_vars).
    pub fn num_points(&self) -> usize {
        1 << self.num_vars
    }

    /// Returns the number of non-zero evaluations stored.
    pub fn num_nonzero(&self) -> usize {
        self.evaluations.len()
    }

    /// Sets the evaluation at a specific point.
    ///
    /// # Arguments
    /// * `index` - Bitmask representing the boolean assignment (0 to 2^num_vars - 1)
    /// * `value` - The evaluation value (zero removes the entry)
    pub fn set_evaluation(&mut self, index: u64, value: F) {
        if index >= (1u64 << self.num_vars) {
            panic!("Index exceeds hypercube size");
        }

        // Find if index already exists
        if let Some(pos) = self.evaluations.iter().position(|(i, _)| *i == index) {
            if value.is_zero() {
                self.evaluations.remove(pos);
            } else {
                self.evaluations[pos].1 = value;
            }
        } else if !value.is_zero() {
            // Insert in sorted order
            let pos = self
                .evaluations
                .binary_search_by_key(&index, |(i, _)| *i)
                .unwrap_or_else(|e| e);
            self.evaluations.insert(pos, (index, value));
        }
    }

    /// Gets the evaluation at a specific point.
    ///
    /// # Arguments
    /// * `index` - Bitmask representing the boolean assignment
    ///
    /// # Returns
    /// The evaluation value, or F::zero() if not stored
    pub fn get_evaluation(&self, index: u64) -> F {
        self.evaluations
            .binary_search_by_key(&index, |(i, _)| *i)
            .ok()
            .map(|idx| self.evaluations[idx].1)
            .unwrap_or_else(F::zero)
    }

    /// Computes the sum of all evaluations in the hypercube.
    /// Useful for sumcheck protocols.
    ///
    /// # Returns
    /// The sum of all non-zero evaluations
    pub fn sum(&self) -> F {
        let mut sum = F::zero();
        for (_, value) in &self.evaluations {
            sum += value;
        }
        sum
    }

    /// Converts a boolean point to its index (bitmask).
    ///
    /// # Arguments
    /// * `point` - Vector of field elements (0 or 1)
    ///
    /// # Returns
    /// The bitmask index, or None if point contains non-boolean values
    pub fn point_to_index(point: &[F]) -> Option<u64> {
        let mut index = 0u64;
        for (i, coord) in point.iter().enumerate() {
            if *coord == F::one() {
                index |= 1u64 << i;
            } else if *coord != F::zero() {
                return None; // Non-boolean coordinate
            }
        }
        Some(index)
    }

    /// Converts an index (bitmask) to a boolean point.
    ///
    /// # Arguments
    /// * `index` - Bitmask representing the boolean assignment
    ///
    /// # Returns
    /// A vector of field elements (0 or 1)
    pub fn index_to_point(index: u64, num_vars: usize) -> Vec<F> {
        let mut point = Vec::with_capacity(num_vars);
        for i in 0..num_vars {
            let bit = ((index >> i) & 1) as u32;
            point.push(if bit == 0 { F::zero() } else { F::one() });
        }
        point
    }

    /// Computes the Hamming weight (number of 1s) in an index.
    ///
    /// # Arguments
    /// * `index` - Bitmask
    ///
    /// # Returns
    /// The number of bits set to 1
    pub fn hamming_weight(index: u64) -> usize {
        index.count_ones() as usize
    }

    /// Returns all indices with a specific Hamming weight.
    ///
    /// # Arguments
    /// * `weight` - The desired Hamming weight
    ///
    /// # Returns
    /// A vector of indices with the specified weight
    pub fn indices_with_weight(&self, weight: usize) -> Vec<u64> {
        let mut indices = Vec::new();
        for i in 0..self.num_points() {
            if Self::hamming_weight(i as u64) == weight {
                indices.push(i as u64);
            }
        }
        indices
    }

    /// Computes the Hamming distance between two indices.
    ///
    /// # Arguments
    /// * `index1` - First bitmask
    /// * `index2` - Second bitmask
    ///
    /// # Returns
    /// The number of bits where they differ
    pub fn hamming_distance(index1: u64, index2: u64) -> usize {
        (index1 ^ index2).count_ones() as usize
    }

    /// Returns an iterator over the non-zero evaluations.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &F)> {
        self.evaluations.iter().map(|(i, v)| (*i, v))
    }

    /// Returns a reference to the internal evaluations vec.
    pub fn evaluations(&self) -> &Vec<(u64, F)> {
        &self.evaluations
    }

    /// Checks if the hypercube is empty (all evaluations are zero).
    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }

    /// Converts to a dense representation (all 2^n evaluations).
    /// Warning: This can be memory-intensive for large n.
    ///
    /// # Returns
    /// A vector of all 2^num_vars evaluations
    pub fn to_dense(&self) -> Vec<F> {
        let mut dense = vec![F::zero(); self.num_points()];
        for (index, value) in &self.evaluations {
            dense[*index as usize] = *value;
        }
        dense
    }

    /// Creates from a dense representation.
    ///
    /// # Arguments
    /// * `num_vars` - Number of variables
    /// * `dense` - Vector of all 2^num_vars evaluations
    pub fn from_dense(num_vars: usize, dense: Vec<F>) -> Self {
        Self::from_evaluations(num_vars, dense)
    }
}

impl<F: Field + fmt::Display> fmt::Display for BooleanHypercube<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BooleanHypercube with {} variables ({} non-zero of {} points):\n",
            self.num_vars,
            self.num_nonzero(),
            self.num_points()
        )?;
        for (index, value) in &self.evaluations {
            let point = Self::index_to_point(*index, self.num_vars);
            write!(f, "  f(")?;
            for (i, coord) in point.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", coord)?;
            }
            write!(f, ") = {}\n", value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::One;
    use ark_std::Zero;

    #[test]
    fn test_polynomial_creation() {
        let poly = UnivariatePolynomial::<Fr>::new();
        assert!(poly.is_zero());
        assert_eq!(poly.degree(), 0);
        assert_eq!(poly.num_terms(), 0);
    }

    #[test]
    fn test_set_and_get_coefficient() {
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(2, Fr::from(3u32));
        poly.set_coefficient(1, Fr::from(2u32));
        poly.set_coefficient(0, Fr::from(1u32));

        assert_eq!(poly.get_coefficient(2), Fr::from(3u32));
        assert_eq!(poly.get_coefficient(1), Fr::from(2u32));
        assert_eq!(poly.get_coefficient(0), Fr::from(1u32));
        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.num_terms(), 3);
    }

    #[test]
    fn test_from_terms() {
        let terms = vec![
            (2, Fr::from(3u32)),
            (0, Fr::from(1u32)),
            (1, Fr::from(2u32)),
        ];
        let poly = UnivariatePolynomial::from_terms(terms);

        // Should be sorted by degree
        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.num_terms(), 3);
        assert_eq!(poly.get_coefficient(0), Fr::from(1u32));
        assert_eq!(poly.get_coefficient(1), Fr::from(2u32));
        assert_eq!(poly.get_coefficient(2), Fr::from(3u32));
    }

    #[test]
    fn test_from_terms_with_duplicates() {
        let terms = vec![
            (1, Fr::from(2u32)),
            (1, Fr::from(3u32)),
            (0, Fr::from(1u32)),
        ];
        let poly = UnivariatePolynomial::from_terms(terms);

        // Duplicates should be summed
        assert_eq!(poly.num_terms(), 2);
        assert_eq!(poly.get_coefficient(1), Fr::from(5u32));
    }

    #[test]
    fn test_polynomial_addition() {
        // p1(x) = 2x^2 + 3x + 1
        let mut p1 = UnivariatePolynomial::<Fr>::new();
        p1.set_coefficient(2, Fr::from(2u32));
        p1.set_coefficient(1, Fr::from(3u32));
        p1.set_coefficient(0, Fr::from(1u32));

        // p2(x) = x^2 + 2x + 3
        let mut p2 = UnivariatePolynomial::<Fr>::new();
        p2.set_coefficient(2, Fr::from(1u32));
        p2.set_coefficient(1, Fr::from(2u32));
        p2.set_coefficient(0, Fr::from(3u32));

        // p1 + p2 = 3x^2 + 5x + 4
        let result = p1 + p2;
        assert_eq!(result.get_coefficient(2), Fr::from(3u32));
        assert_eq!(result.get_coefficient(1), Fr::from(5u32));
        assert_eq!(result.get_coefficient(0), Fr::from(4u32));
    }

    #[test]
    fn test_polynomial_subtraction() {
        // p1(x) = 2x^2 + 3x + 1
        let mut p1 = UnivariatePolynomial::<Fr>::new();
        p1.set_coefficient(2, Fr::from(2u32));
        p1.set_coefficient(1, Fr::from(3u32));
        p1.set_coefficient(0, Fr::from(1u32));

        // p2(x) = x^2 + 2x + 3
        let mut p2 = UnivariatePolynomial::<Fr>::new();
        p2.set_coefficient(2, Fr::from(1u32));
        p2.set_coefficient(1, Fr::from(2u32));
        p2.set_coefficient(0, Fr::from(3u32));

        // p1 - p2 = x^2 + x - 2
        let result = p1 - p2;
        assert_eq!(result.get_coefficient(2), Fr::from(1u32));
        assert_eq!(result.get_coefficient(1), Fr::from(1u32));
        assert_eq!(result.get_coefficient(0), -Fr::from(2u32));
    }

    #[test]
    fn test_polynomial_multiplication() {
        // p1(x) = x + 1
        let mut p1 = UnivariatePolynomial::<Fr>::new();
        p1.set_coefficient(1, Fr::from(1u32));
        p1.set_coefficient(0, Fr::from(1u32));

        // p2(x) = x + 2
        let mut p2 = UnivariatePolynomial::<Fr>::new();
        p2.set_coefficient(1, Fr::from(1u32));
        p2.set_coefficient(0, Fr::from(2u32));

        // p1 * p2 = x^2 + 3x + 2
        let result = p1 * p2;
        assert_eq!(result.get_coefficient(2), Fr::from(1u32));
        assert_eq!(result.get_coefficient(1), Fr::from(3u32));
        assert_eq!(result.get_coefficient(0), Fr::from(2u32));
    }

    #[test]
    fn test_polynomial_multiplication_by_zero() {
        let mut p1 = UnivariatePolynomial::<Fr>::new();
        p1.set_coefficient(2, Fr::from(2u32));
        p1.set_coefficient(1, Fr::from(3u32));

        let p2 = UnivariatePolynomial::<Fr>::new();

        let result = p1 * p2;
        assert!(result.is_zero());
    }

    #[test]
    fn test_lagrange_interpolation_linear() {
        // Two points: (0, 1) and (1, 2)
        // Should give polynomial: y = x + 1
        let points = vec![
            (Fr::from(0u32), Fr::from(1u32)),
            (Fr::from(1u32), Fr::from(2u32)),
        ];
        let poly = lagrange_interpolation(&points);

        assert_eq!(poly.get_coefficient(1), Fr::from(1u32));
        assert_eq!(poly.get_coefficient(0), Fr::from(1u32));
    }

    #[test]
    fn test_lagrange_interpolation_quadratic() {
        // Three points: (0, 0), (1, 1), (2, 4)
        // Should give polynomial: y = x^2
        let points = vec![
            (Fr::from(0u32), Fr::from(0u32)),
            (Fr::from(1u32), Fr::from(1u32)),
            (Fr::from(2u32), Fr::from(4u32)),
        ];
        let poly = lagrange_interpolation(&points);

        // Verify the polynomial passes through all points
        assert_eq!(poly.evaluate_horner(Fr::from(0u32)), Fr::from(0u32));
        assert_eq!(poly.evaluate_horner(Fr::from(1u32)), Fr::from(1u32));
        assert_eq!(poly.evaluate_horner(Fr::from(2u32)), Fr::from(4u32));
    }

    #[test]
    fn test_lagrange_interpolation_for_three_points() {
        // three points [(0,8), (1,10), (2,16)]
        //should give polynomial: y = 2xˆ2 + 8
        let points = vec![
            (Fr::from(0u32), Fr::from(8u32)),
            (Fr::from(1u32), Fr::from(10u32)),
            (Fr::from(2u32), Fr::from(16u32)),
        ];
        let poly = lagrange_interpolation(&points);
        println!("the polynomial is {}", poly);
        assert_eq!(poly.evaluate_horner(Fr::from(0u32)), Fr::from(8u32));
        assert_eq!(poly.evaluate_horner(Fr::from(1u32)), Fr::from(10u32));
        assert_eq!(poly.evaluate_horner(Fr::from(2u32)), Fr::from(16u32));
    }

    #[test]
    fn test_lagrange_interpolation_cubic() {
        // Four points: (1, 1), (2, 8), (3, 27), (4, 64)
        // Should give polynomial: y = x^3
        let points = vec![
            (Fr::from(1u32), Fr::from(1u32)),
            (Fr::from(2u32), Fr::from(8u32)),
            (Fr::from(3u32), Fr::from(27u32)),
            (Fr::from(4u32), Fr::from(64u32)),
        ];
        let poly = lagrange_interpolation(&points);

        // Verify the polynomial passes through all points
        for (x, y) in points {
            let result = poly.evaluate_horner(x);
            assert_eq!(result, y, "Expected {}, got {}", y, result);
        }
    }

    #[test]
    fn test_evaluate_horner() {
        // p(x) = 2x^2 + 3x + 1
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(2, Fr::from(2u32));
        poly.set_coefficient(1, Fr::from(3u32));
        poly.set_coefficient(0, Fr::from(1u32));

        // p(2) = 2*4 + 3*2 + 1 = 8 + 6 + 1 = 15
        assert_eq!(poly.evaluate_horner(Fr::from(2u32)), Fr::from(15u32));

        // p(0) = 1
        assert_eq!(poly.evaluate_horner(Fr::from(0u32)), Fr::from(1u32));

        // p(-1) = 2*1 + 3*(-1) + 1 = 2 - 3 + 1 = 0
        assert_eq!(poly.evaluate_horner(-Fr::from(1u32)), Fr::from(0u32));
    }

    #[test]
    fn test_evaluate_direct() {
        // p(x) = 2x^2 + 3x + 1
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(2, Fr::from(2u32));
        poly.set_coefficient(1, Fr::from(3u32));
        poly.set_coefficient(0, Fr::from(1u32));

        // p(2) = 2*4 + 3*2 + 1 = 8 + 6 + 1 = 15
        assert_eq!(poly.evaluate_direct(Fr::from(2u32)), Fr::from(15u32));

        // p(0) = 1
        assert_eq!(poly.evaluate_direct(Fr::from(0u32)), Fr::from(1u32));

        // p(1) = 2*1 + 3*(1) + 1 = 2 + 3 + 1 = 6
        assert_eq!(poly.evaluate_direct(Fr::from(1u32)), Fr::from(6u32));
    }

    #[test]
    fn test_horner_vs_direct_evaluation() {
        // p(x) = 5x^3 + 2x^2 + 7x + 3
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(3, Fr::from(5u32));
        poly.set_coefficient(2, Fr::from(2u32));
        poly.set_coefficient(1, Fr::from(7u32));
        poly.set_coefficient(0, Fr::from(3u32));

        let x = Fr::from(3u32);
        let horner_result = poly.evaluate_horner(x);
        let direct_result = poly.evaluate_direct(x);

        assert_eq!(horner_result, direct_result);
    }

    #[test]
    fn test_sparse_representation() {
        // Create a polynomial with only a few non-zero terms
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(100, Fr::from(1u32));
        poly.set_coefficient(50, Fr::from(2u32));
        poly.set_coefficient(0, Fr::from(3u32));

        // Should only store 3 terms, not 101
        assert_eq!(poly.num_terms(), 3);
        assert_eq!(poly.degree(), 100);
    }

    #[test]
    fn test_zero_coefficient_removal() {
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(2, Fr::from(5u32));
        poly.set_coefficient(1, Fr::from(3u32));

        // Setting a coefficient to zero should remove it
        poly.set_coefficient(2, Fr::zero());
        assert_eq!(poly.num_terms(), 1);
        assert_eq!(poly.get_coefficient(2), Fr::zero());
    }

    #[test]
    fn test_complex_polynomial_operations() {
        // p1(x) = x^2 + 2x + 1 = (x + 1)^2
        let mut p1 = UnivariatePolynomial::<Fr>::new();
        p1.set_coefficient(2, Fr::from(1u32));
        p1.set_coefficient(1, Fr::from(2u32));
        p1.set_coefficient(0, Fr::from(1u32));

        // p2(x) = x - 1
        let mut p2 = UnivariatePolynomial::<Fr>::new();
        p2.set_coefficient(1, Fr::from(1u32));
        p2.set_coefficient(0, -Fr::from(1u32));

        // p1 * p2 = (x + 1)^2 * (x - 1) = (x^2 + 2x + 1)(x - 1)
        //         = x^3 + 2x^2 + x - x^2 - 2x - 1
        //         = x^3 + x^2 - x - 1
        let result = p1 * p2;

        assert_eq!(result.get_coefficient(3), Fr::from(1u32));
        assert_eq!(result.get_coefficient(2), Fr::from(1u32));
        assert_eq!(result.get_coefficient(1), -Fr::from(1u32));
        assert_eq!(result.get_coefficient(0), -Fr::from(1u32));
    }

    #[test]
    fn test_complexity_analysis() {
        // p(x) = x^100 + x^50 + x^10 + 1
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(100, Fr::from(1u32));
        poly.set_coefficient(50, Fr::from(1u32));
        poly.set_coefficient(10, Fr::from(1u32));
        poly.set_coefficient(0, Fr::from(1u32));

        // Horner method: 100 multiplications (degree)
        assert_eq!(poly.horner_complexity(), 100);

        // Direct method: 100 + 50 + 10 = 160 multiplications
        assert_eq!(poly.direct_complexity(), 160);
    }

    #[test]
    fn test_vec_based_sparse_efficiency() {
        // Create a very sparse polynomial
        let mut poly = UnivariatePolynomial::<Fr>::new();
        poly.set_coefficient(1000000, Fr::from(1u32));
        poly.set_coefficient(500000, Fr::from(2u32));
        poly.set_coefficient(100, Fr::from(3u32));
        poly.set_coefficient(0, Fr::from(5u32));

        // Only 4 terms stored, not 1000001
        assert_eq!(poly.num_terms(), 4);
        assert_eq!(poly.degree(), 1000000);

        // Horner evaluation is still efficient
        let result = poly.evaluate_horner(Fr::from(2u32));
        assert!(!result.is_zero());
    }

    #[test]
    fn test_shamirs_secret_sharing() {
        // Secret: 42 (constant term)
        // Create polynomial: p(x) = 42 + 5x + 3x^2
        let mut secret_poly = UnivariatePolynomial::<Fr>::new();
        secret_poly.set_coefficient(0, Fr::from(42u32));
        secret_poly.set_coefficient(1, Fr::from(5u32));
        secret_poly.set_coefficient(2, Fr::from(3u32));

        // Generate shares at points 1, 2, 3, 4, 5
        let mut shares = Vec::new();
        for i in 1..=5 {
            let x = Fr::from(i as u32);
            let y = secret_poly.evaluate_horner(x);
            shares.push((x, y));
        }

        // Reconstruct with any 3 shares (threshold = 3)
        let reconstruction_shares = vec![shares[0], shares[1], shares[2]];
        let reconstructed_poly = lagrange_interpolation(&reconstruction_shares);

        let reconstructed_secret = reconstructed_poly.get_coefficient(0);
        assert_eq!(reconstructed_secret, Fr::from(42u32));
    }

    // ========================================================================
    // Boolean Hypercube Tests
    // ========================================================================

    #[test]
    fn test_boolean_hypercube_creation() {
        let hypercube = BooleanHypercube::<Fr>::new(2);
        assert_eq!(hypercube.num_vars(), 2);
        assert_eq!(hypercube.num_points(), 4);
        assert!(hypercube.is_empty());
    }

    #[test]
    fn test_boolean_hypercube_from_evaluations() {
        let evals = vec![Fr::from(1u32), Fr::zero(), Fr::from(2u32), Fr::zero()];
        let hypercube = BooleanHypercube::from_evaluations(2, evals);
        assert_eq!(hypercube.num_vars(), 2);
        assert_eq!(hypercube.num_nonzero(), 2);
        assert_eq!(hypercube.get_evaluation(0), Fr::from(1u32));
        assert_eq!(hypercube.get_evaluation(2), Fr::from(2u32));
    }

    #[test]
    fn test_boolean_hypercube_set_get_evaluation() {
        let mut hypercube = BooleanHypercube::<Fr>::new(2);
        hypercube.set_evaluation(0, Fr::from(5u32));
        hypercube.set_evaluation(3, Fr::from(7u32));

        assert_eq!(hypercube.get_evaluation(0), Fr::from(5u32));
        assert_eq!(hypercube.get_evaluation(3), Fr::from(7u32));
        assert_eq!(hypercube.get_evaluation(1), Fr::zero());
        assert_eq!(hypercube.num_nonzero(), 2);
    }

    #[test]
    fn test_boolean_hypercube_sum() {
        let evals = vec![
            Fr::from(1u32),
            Fr::from(2u32),
            Fr::from(3u32),
            Fr::from(4u32),
        ];
        let hypercube = BooleanHypercube::from_evaluations(2, evals);
        assert_eq!(hypercube.sum(), Fr::from(10u32));
    }

    #[test]
    fn test_boolean_hypercube_point_to_index() {
        let point = vec![Fr::zero(), Fr::one()];
        let index = BooleanHypercube::<Fr>::point_to_index(&point).unwrap();
        assert_eq!(index, 2u64); // 0b10
    }

    #[test]
    fn test_boolean_hypercube_index_to_point() {
        let point = BooleanHypercube::<Fr>::index_to_point(3, 2);
        assert_eq!(point[0], Fr::one());
        assert_eq!(point[1], Fr::one());
    }

    #[test]
    fn test_boolean_hypercube_hamming_weight() {
        assert_eq!(BooleanHypercube::<Fr>::hamming_weight(0b101), 2);
        assert_eq!(BooleanHypercube::<Fr>::hamming_weight(0b111), 3);
        assert_eq!(BooleanHypercube::<Fr>::hamming_weight(0b000), 0);
    }

    #[test]
    fn test_boolean_hypercube_hamming_distance() {
        assert_eq!(BooleanHypercube::<Fr>::hamming_distance(0b101, 0b111), 1);
        assert_eq!(BooleanHypercube::<Fr>::hamming_distance(0b000, 0b111), 3);
    }

    #[test]
    fn test_boolean_hypercube_indices_with_weight() {
        let hypercube = BooleanHypercube::<Fr>::new(3);
        let weight_2 = hypercube.indices_with_weight(2);
        assert_eq!(weight_2.len(), 3); // C(3,2) = 3
    }

    #[test]
    fn test_boolean_hypercube_to_dense() {
        let mut hypercube = BooleanHypercube::<Fr>::new(2);
        hypercube.set_evaluation(0, Fr::from(1u32));
        hypercube.set_evaluation(3, Fr::from(4u32));

        let dense = hypercube.to_dense();
        assert_eq!(dense.len(), 4);
        assert_eq!(dense[0], Fr::from(1u32));
        assert_eq!(dense[1], Fr::zero());
        assert_eq!(dense[2], Fr::zero());
        assert_eq!(dense[3], Fr::from(4u32));
    }

    #[test]
    fn test_boolean_hypercube_from_dense() {
        let dense = vec![Fr::from(1u32), Fr::zero(), Fr::from(2u32), Fr::zero()];
        let hypercube = BooleanHypercube::from_dense(2, dense);
        assert_eq!(hypercube.num_nonzero(), 2);
        assert_eq!(hypercube.get_evaluation(0), Fr::from(1u32));
        assert_eq!(hypercube.get_evaluation(2), Fr::from(2u32));
    }

    #[test]
    fn test_boolean_hypercube_iterator() {
        let mut hypercube = BooleanHypercube::<Fr>::new(2);
        hypercube.set_evaluation(1, Fr::from(5u32));
        hypercube.set_evaluation(3, Fr::from(7u32));

        let count = hypercube.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_boolean_hypercube_sparse_efficiency() {
        // Create a hypercube with many variables but few non-zero evaluations
        let mut hypercube = BooleanHypercube::<Fr>::new(10);
        hypercube.set_evaluation(0, Fr::from(1u32));
        hypercube.set_evaluation(512, Fr::from(2u32));
        hypercube.set_evaluation(1023, Fr::from(3u32));

        assert_eq!(hypercube.num_vars(), 10);
        assert_eq!(hypercube.num_points(), 1024);
        assert_eq!(hypercube.num_nonzero(), 3);
    }
}
