use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::vec::Vec;

/// Univariate Polynomial Implementation using Arkworks
///
/// A univariate polynomial is a polynomial in a single variable, typically represented as:
/// P(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
///
/// This module provides operations for creating, evaluating, and manipulating univariate polynomials
/// over finite fields using the arkworks library.

/// Represents a univariate polynomial with coefficients in a prime field
#[derive(Clone, Debug, PartialEq)]
pub struct UnivariatePoly<F: PrimeField> {
    /// The underlying polynomial from arkworks
    poly: DensePolynomial<F>,
}

impl<F: PrimeField> UnivariatePoly<F> {
    /// Create a new univariate polynomial from a vector of coefficients
    ///
    /// The coefficients are ordered from lowest degree to highest degree.
    /// For example, [a_0, a_1, a_2] represents a_0 + a_1*x + a_2*x^2
    ///
    /// # Arguments
    /// * `coefficients` - Vector of field elements representing polynomial coefficients
    ///
    /// # Example
    /// ```ignore
    /// let coeffs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    /// let poly = UnivariatePoly::new(coeffs); // 1 + 2x + 3x^2
    /// ```
    pub fn new(coefficients: Vec<F>) -> Self {
        Self {
            poly: DensePolynomial::from_coefficients_vec(coefficients),
        }
    }

    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self {
            poly: DensePolynomial::from_coefficients_vec(vec![F::ZERO]),
        }
    }

    /// Create a constant polynomial
    ///
    /// # Arguments
    /// * `constant` - The constant value
    pub fn constant(constant: F) -> Self {
        Self {
            poly: DensePolynomial::from_coefficients_vec(vec![constant]),
        }
    }

    /// Get the degree of the polynomial
    ///
    /// Returns the highest power of x with a non-zero coefficient.
    /// The zero polynomial has degree 0.
    pub fn degree(&self) -> usize {
        self.poly.degree()
    }

    /// Get the coefficients of the polynomial
    ///
    /// Returns a reference to the coefficient vector (lowest degree first)
    pub fn coefficients(&self) -> &[F] {
        self.poly.coeffs()
    }

    /// Evaluate the polynomial at a given point
    ///
    /// Computes P(x) using Horner's method for efficiency
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate the polynomial
    ///
    /// # Example
    /// ```ignore
    /// let coeffs = vec![Fr::from(1u64), Fr::from(2u64)]; // 1 + 2x
    /// let poly = UnivariatePoly::new(coeffs);
    /// let result = poly.evaluate(&Fr::from(3u64)); // 1 + 2*3 = 7
    /// ```
    pub fn evaluate(&self, x: &F) -> F {
        self.poly.evaluate(x)
    }

    /// Add two polynomials
    ///
    /// Returns a new polynomial that is the sum of self and other
    pub fn add(&self, other: &UnivariatePoly<F>) -> UnivariatePoly<F> {
        let mut result_coeffs = self.poly.coeffs().to_vec();
        let other_coeffs = other.poly.coeffs();

        // Extend result if other is longer
        if other_coeffs.len() > result_coeffs.len() {
            result_coeffs.resize(other_coeffs.len(), F::ZERO);
        }

        // Add coefficients
        for (i, &coeff) in other_coeffs.iter().enumerate() {
            result_coeffs[i] += coeff;
        }

        UnivariatePoly::new(result_coeffs)
    }

    /// Subtract two polynomials
    ///
    /// Returns a new polynomial that is self minus other
    pub fn subtract(&self, other: &UnivariatePoly<F>) -> UnivariatePoly<F> {
        let mut result_coeffs = self.poly.coeffs().to_vec();
        let other_coeffs = other.poly.coeffs();

        // Extend result if other is longer
        if other_coeffs.len() > result_coeffs.len() {
            result_coeffs.resize(other_coeffs.len(), F::ZERO);
        }

        // Subtract coefficients
        for (i, &coeff) in other_coeffs.iter().enumerate() {
            result_coeffs[i] -= coeff;
        }

        UnivariatePoly::new(result_coeffs)
    }

    /// Multiply two polynomials
    ///
    /// Returns a new polynomial that is the product of self and other
    pub fn multiply(&self, other: &UnivariatePoly<F>) -> UnivariatePoly<F> {
        let self_coeffs = self.poly.coeffs();
        let other_coeffs = other.poly.coeffs();

        if self_coeffs.is_empty() || other_coeffs.is_empty() {
            return UnivariatePoly::zero();
        }

        // Result polynomial has degree = deg(self) + deg(other)
        let result_len = self_coeffs.len() + other_coeffs.len() - 1;
        let mut result_coeffs = vec![F::ZERO; result_len];

        // Multiply each coefficient of self with each coefficient of other
        for (i, &self_coeff) in self_coeffs.iter().enumerate() {
            for (j, &other_coeff) in other_coeffs.iter().enumerate() {
                result_coeffs[i + j] += self_coeff * other_coeff;
            }
        }

        UnivariatePoly::new(result_coeffs)
    }

    /// Multiply the polynomial by a scalar
    ///
    /// Returns a new polynomial with all coefficients multiplied by the scalar
    pub fn scalar_multiply(&self, scalar: F) -> UnivariatePoly<F> {
        let coeffs = self
            .poly
            .coeffs()
            .iter()
            .map(|&c| c * scalar)
            .collect();
        UnivariatePoly::new(coeffs)
    }

    /// Compute the derivative of the polynomial
    ///
    /// If P(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
    /// Then P'(x) = a_1 + 2*a_2*x + 3*a_3*x^2 + ... + n*a_n*x^(n-1)
    pub fn derivative(&self) -> UnivariatePoly<F> {
        let coeffs = self.poly.coeffs();

        if coeffs.len() <= 1 {
            return UnivariatePoly::zero();
        }

        let mut derivative_coeffs = Vec::with_capacity(coeffs.len() - 1);

        for i in 1..coeffs.len() {
            derivative_coeffs.push(coeffs[i] * F::from(i as u64));
        }

        UnivariatePoly::new(derivative_coeffs)
    }

    /// Evaluate the polynomial at multiple points
    ///
    /// Returns a vector of evaluations at the given points
    pub fn evaluate_at_points(&self, points: &[F]) -> Vec<F> {
        points.iter().map(|p| self.evaluate(p)).collect()
    }

    /// Check if the polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.poly.coeffs().iter().all(|&c| c == F::ZERO)
    }

    /// Get the leading coefficient (coefficient of highest degree term)
    pub fn leading_coefficient(&self) -> Option<F> {
        let coeffs = self.poly.coeffs();
        if coeffs.is_empty() {
            None
        } else {
            Some(coeffs[coeffs.len() - 1])
        }
    }

    /// Compose two polynomials: compute P(Q(x))
    ///
    /// This computes the composition of self with other polynomial
    pub fn compose(&self, other: &UnivariatePoly<F>) -> UnivariatePoly<F> {
        let coeffs = self.poly.coeffs();

        if coeffs.is_empty() {
            return UnivariatePoly::zero();
        }

        // Start with the constant term
        let mut result = UnivariatePoly::constant(coeffs[0]);

        // Build up the composition using Horner's method
        let mut other_power = other.clone();

        for &coeff in &coeffs[1..] {
            let term = other_power.scalar_multiply(coeff);
            result = result.add(&term);
            other_power = other_power.multiply(other);
        }

        result
    }

    /// Shift the polynomial: compute P(x + shift)
    ///
    /// This returns a new polynomial where all x values are shifted by the given amount
    pub fn shift(&self, shift: F) -> UnivariatePoly<F> {
        let shift_poly = UnivariatePoly::new(vec![shift, F::ONE]); // x + shift
        self.compose(&shift_poly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    type TestField = Fr;

    #[test]
    fn test_create_polynomial() {
        let coeffs = vec![
            TestField::from(1u64),
            TestField::from(2u64),
            TestField::from(3u64),
        ];
        let poly = UnivariatePoly::new(coeffs);

        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.coefficients().len(), 3);
    }

    #[test]
    fn test_zero_polynomial() {
        let zero = UnivariatePoly::<TestField>::zero();
        assert!(zero.is_zero());
    }

    #[test]
    fn test_constant_polynomial() {
        let constant = UnivariatePoly::constant(TestField::from(5u64));
        assert_eq!(constant.degree(), 0);
        assert_eq!(
            constant.evaluate(&TestField::from(100u64)),
            TestField::from(5u64)
        );
    }

    #[test]
    fn test_evaluate_polynomial() {
        // P(x) = 1 + 2x + 3x^2
        let coeffs = vec![
            TestField::from(1u64),
            TestField::from(2u64),
            TestField::from(3u64),
        ];
        let poly = UnivariatePoly::new(coeffs);

        // P(0) = 1
        assert_eq!(poly.evaluate(&TestField::from(0u64)), TestField::from(1u64));

        // P(1) = 1 + 2 + 3 = 6
        assert_eq!(poly.evaluate(&TestField::from(1u64)), TestField::from(6u64));

        // P(2) = 1 + 4 + 12 = 17
        assert_eq!(poly.evaluate(&TestField::from(2u64)), TestField::from(17u64));
    }

    #[test]
    fn test_add_polynomials() {
        // P(x) = 1 + 2x
        let p_coeffs = vec![TestField::from(1u64), TestField::from(2u64)];
        let p = UnivariatePoly::new(p_coeffs);

        // Q(x) = 3 + 4x
        let q_coeffs = vec![TestField::from(3u64), TestField::from(4u64)];
        let q = UnivariatePoly::new(q_coeffs);

        // P(x) + Q(x) = 4 + 6x
        let sum = p.add(&q);
        assert_eq!(sum.evaluate(&TestField::from(0u64)), TestField::from(4u64));
        assert_eq!(sum.evaluate(&TestField::from(1u64)), TestField::from(10u64));
    }

    #[test]
    fn test_subtract_polynomials() {
        // P(x) = 5 + 3x
        let p_coeffs = vec![TestField::from(5u64), TestField::from(3u64)];
        let p = UnivariatePoly::new(p_coeffs);

        // Q(x) = 2 + 1x
        let q_coeffs = vec![TestField::from(2u64), TestField::from(1u64)];
        let q = UnivariatePoly::new(q_coeffs);

        // P(x) - Q(x) = 3 + 2x
        let diff = p.subtract(&q);
        assert_eq!(diff.evaluate(&TestField::from(0u64)), TestField::from(3u64));
        assert_eq!(diff.evaluate(&TestField::from(1u64)), TestField::from(5u64));
    }

    #[test]
    fn test_multiply_polynomials() {
        // P(x) = 1 + x
        let p_coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let p = UnivariatePoly::new(p_coeffs);

        // Q(x) = 1 + x
        let q_coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let q = UnivariatePoly::new(q_coeffs);

        // P(x) * Q(x) = (1 + x)^2 = 1 + 2x + x^2
        let product = p.multiply(&q);
        assert_eq!(product.degree(), 2);
        assert_eq!(product.evaluate(&TestField::from(0u64)), TestField::from(1u64));
        assert_eq!(product.evaluate(&TestField::from(1u64)), TestField::from(4u64));
        assert_eq!(product.evaluate(&TestField::from(2u64)), TestField::from(9u64));
    }

    #[test]
    fn test_scalar_multiply() {
        // P(x) = 1 + 2x + 3x^2
        let coeffs = vec![
            TestField::from(1u64),
            TestField::from(2u64),
            TestField::from(3u64),
        ];
        let poly = UnivariatePoly::new(coeffs);

        // 2 * P(x) = 2 + 4x + 6x^2
        let scaled = poly.scalar_multiply(TestField::from(2u64));
        assert_eq!(scaled.evaluate(&TestField::from(1u64)), TestField::from(12u64));
    }

    #[test]
    fn test_derivative() {
        // P(x) = 1 + 2x + 3x^2
        let coeffs = vec![
            TestField::from(1u64),
            TestField::from(2u64),
            TestField::from(3u64),
        ];
        let poly = UnivariatePoly::new(coeffs);

        // P'(x) = 2 + 6x
        let deriv = poly.derivative();
        assert_eq!(deriv.evaluate(&TestField::from(0u64)), TestField::from(2u64));
        assert_eq!(deriv.evaluate(&TestField::from(1u64)), TestField::from(8u64));
    }

    #[test]
    fn test_evaluate_at_points() {
        // P(x) = 1 + x
        let coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let poly = UnivariatePoly::new(coeffs);

        let points = vec![
            TestField::from(0u64),
            TestField::from(1u64),
            TestField::from(2u64),
        ];
        let results = poly.evaluate_at_points(&points);

        assert_eq!(results[0], TestField::from(1u64));
        assert_eq!(results[1], TestField::from(2u64));
        assert_eq!(results[2], TestField::from(3u64));
    }

    #[test]
    fn test_leading_coefficient() {
        let coeffs = vec![
            TestField::from(1u64),
            TestField::from(2u64),
            TestField::from(3u64),
        ];
        let poly = UnivariatePoly::new(coeffs);

        assert_eq!(
            poly.leading_coefficient(),
            Some(TestField::from(3u64))
        );
    }

    #[test]
    fn test_compose_polynomials() {
        // P(x) = 1 + x
        let p_coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let p = UnivariatePoly::new(p_coeffs);

        // Q(x) = 2 + x
        let q_coeffs = vec![TestField::from(2u64), TestField::from(1u64)];
        let q = UnivariatePoly::new(q_coeffs);

        // P(Q(x)) = 1 + (2 + x) = 3 + x
        let composed = p.compose(&q);
        assert_eq!(composed.evaluate(&TestField::from(0u64)), TestField::from(3u64));
        assert_eq!(composed.evaluate(&TestField::from(1u64)), TestField::from(4u64));
    }

    #[test]
    fn test_shift_polynomial() {
        // P(x) = 1 + x
        let coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let poly = UnivariatePoly::new(coeffs);

        // P(x + 2) = 1 + (x + 2) = 3 + x
        let shifted = poly.shift(TestField::from(2u64));
        assert_eq!(shifted.evaluate(&TestField::from(0u64)), TestField::from(3u64));
        assert_eq!(shifted.evaluate(&TestField::from(1u64)), TestField::from(4u64));
    }

    #[test]
    fn test_polynomial_operations_chain() {
        // P(x) = 1 + x
        let p_coeffs = vec![TestField::from(1u64), TestField::from(1u64)];
        let p = UnivariatePoly::new(p_coeffs);

        // Q(x) = 2 + x
        let q_coeffs = vec![TestField::from(2u64), TestField::from(1u64)];
        let q = UnivariatePoly::new(q_coeffs);

        // (P + Q) * 2 = (3 + 2x) * 2 = 6 + 4x
        let result = p.add(&q).scalar_multiply(TestField::from(2u64));
        assert_eq!(result.evaluate(&TestField::from(0u64)), TestField::from(6u64));
        assert_eq!(result.evaluate(&TestField::from(1u64)), TestField::from(10u64));
    }
}
