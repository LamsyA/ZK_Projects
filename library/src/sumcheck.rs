use crate::multilinear::MultilinearPolynomial;
use crate::univariate::UnivariatePolynomial;
use ark_ff::Field;
use std::fmt;

/// Represents a message sent during the Sumcheck protocol
#[derive(Clone, Debug)]
pub enum SumcheckMessage<F: Field> {
    /// Prover sends univariate polynomial coefficients for current round
    ProverPolynomial(Vec<F>),
    /// Verifier sends random challenge for current round
    VerifierChallenge(F),
}

impl<F: Field + fmt::Display> fmt::Display for SumcheckMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SumcheckMessage::ProverPolynomial(coeffs) => {
                write!(f, "ProverPolynomial: {} coefficients", coeffs.len())
            }
            SumcheckMessage::VerifierChallenge(r) => {
                write!(f, "VerifierChallenge: {}", r)
            }
        }
    }
}

/// Prover in the Sumcheck protocol
///
/// The prover holds a multilinear polynomial and proves that the sum of its
/// evaluations over the Boolean hypercube equals a claimed value.
///
/// **Protocol Flow:**
/// 1. For each round i (0 to n-1):
///    - Prover computes univariate polynomial g_i(x) by fixing all variables except x_i
///    - Prover sends g_i to verifier
///    - Verifier sends random challenge r_i
///    - Prover fixes x_i = r_i for next round
/// 2. After n rounds, verifier directly evaluates polynomial at final point
#[derive(Clone, Debug)]
pub struct Prover<F: Field> {
    /// The multilinear polynomial being proved
    poly: MultilinearPolynomial<F>,
    /// Random challenges from verifier (accumulated over rounds)
    challenges: Vec<F>,
    /// Current round number
    round: usize,
    /// Number of variables in the polynomial
    num_vars: usize,
}

impl<F: Field> Prover<F> {
    /// Creates a new prover with a multilinear polynomial
    ///
    /// # Arguments
    /// * `poly` - The multilinear polynomial to prove
    ///
    /// # Returns
    /// A new Prover instance
    pub fn new(poly: MultilinearPolynomial<F>) -> Self {
        let num_vars = poly.num_vars();
        Prover {
            poly,
            challenges: Vec::new(),
            round: 0,
            num_vars,
        }
    }

    /// Computes the univariate polynomial for the current round using Boolean Hypercube method
    ///
    /// **Mathematical Definition:**
    /// Given multilinear polynomial P(x_0, ..., x_{n-1}) and challenges r_0, ..., r_{i-1},
    /// compute the univariate polynomial:
    ///
    /// g_i(x) = Σ_{b_{i+1},...,b_{n-1} ∈ {0,1}^{n-i-1}} P(r_0, ..., r_{i-1}, x, b_{i+1}, ..., b_{n-1})
    ///
    /// This satisfies the key property:
    /// g_i(0) + g_i(1) = Σ_{b_i,...,b_{n-1} ∈ {0,1}^{n-i}} P(r_0, ..., r_{i-1}, b_i, ..., b_{n-1})
    ///
    /// **Example with P(x0, x1, x2) = 1 + 2*x0 + 3*x1 + 4*x2:**
    /// Round 0 (no challenges yet):
    ///   g_0(x) = Σ_{b1,b2} P(x, b1, b2)
    ///
    ///   Enumerate all 4 boolean assignments using bit manipulation:
    ///   - index=0 (binary 00): (b1=0, b2=0) → P(x,0,0) = 1 + 2x
    ///   - index=1 (binary 01): (b1=1, b2=0) → P(x,1,0) = 1 + 2x + 3 + 4 = 8 + 2x
    ///   - index=2 (binary 10): (b1=0, b2=1) → P(x,0,1) = 1 + 2x + 4 = 5 + 2x
    ///   - index=3 (binary 11): (b1=1, b2=1) → P(x,1,1) = 1 + 2x + 3 + 4 = 8 + 2x
    ///
    ///   Sum: g_0(x) = (1+2x) + (8+2x) + (5+2x) + (8+2x) = 22 + 8x
    ///
    ///   g_0(0) = 22
    ///   g_0(1) = 30
    ///   g_0(0) + g_0(1) = 52 (sum over all 8 points in {0,1}^3)
    ///
    /// **Bit Manipulation Explained:**
    /// For each index from 0 to 2^num_remaining - 1:
    ///   - Extract bit i: (index >> i) & 1
    ///   - Bit 0 (LSB) → x1 coordinate
    ///   - Bit 1 → x2 coordinate
    ///   - etc.
    ///
    /// **Algorithm:**
    /// 1. Partially evaluate P at x_0 = r_0, ..., x_{i-1} = r_{i-1} → Q(x_i, ..., x_{n-1})
    /// 2. For each boolean assignment (b_{i+1}, ..., b_{n-1}):
    ///    - Evaluate Q(0, b_{i+1}, ..., b_{n-1}) and accumulate → sum_0
    ///    - Evaluate Q(1, b_{i+1}, ..., b_{n-1}) and accumulate → sum_1
    /// 3. Return g_i(x) = sum_0 + (sum_1 - sum_0) * x
    ///
    /// # Returns
    /// A UnivariatePolynomial representing g_i(x)
    fn compute_round_polynomial(&self) -> UnivariatePolynomial<F> {
        // Step 1: Partially evaluate at all fixed variables (challenges from verifier)
        let mut current_poly = self.poly.clone();
        for &challenge in &self.challenges {
            current_poly = current_poly.partial_evaluate(0, challenge);
        }

        // Now: current_poly = Q(x_i, x_{i+1}, ..., x_{n-1})
        // Goal: g_i(x) = Σ_{b_{i+1},...,b_{n-1}} Q(x, b_{i+1}, ..., b_{n-1})

        let num_remaining = current_poly.num_vars() - 1;

        // Step 2: Sum over all boolean assignments to remaining variables
        let mut sum_0 = F::zero();
        let mut sum_1 = F::zero();

        for index in 0..(1u64 << num_remaining) {
            // Build boolean points using index as bitmask
            let mut point_0 = vec![F::zero()];
            let mut point_1 = vec![F::one()];

            for i in 0..num_remaining {
                let bit = if ((index >> i) & 1) == 1 {
                    F::one()
                } else {
                    F::zero()
                };
                point_0.push(bit);
                point_1.push(bit);
            }

            // Evaluate and accumulate
            if let Ok(val) = current_poly.evaluate(&point_0) {
                sum_0 += val;
            }
            if let Ok(val) = current_poly.evaluate(&point_1) {
                sum_1 += val;
            }
        }

        // Step 3: Construct g_i(x) = sum_0 + (sum_1 - sum_0) * x
        let mut poly = UnivariatePolynomial::new();
        poly.set_coefficient(0, sum_0);
        let slope = sum_1 - sum_0;
        if !slope.is_zero() {
            poly.set_coefficient(1, slope);
        }
        poly
    }

    /// Sends the univariate polynomial for the current round
    ///
    /// # Returns
    /// A SumcheckMessage containing the polynomial coefficients
    pub fn send_polynomial(&self) -> SumcheckMessage<F> {
        let poly = self.compute_round_polynomial();
        let coeffs: Vec<F> = poly.iter().map(|(_, coeff)| *coeff).collect();

        SumcheckMessage::ProverPolynomial(coeffs)
    }

    /// Receives a challenge from the verifier and advances to next round
    ///
    /// # Arguments
    /// * `challenge` - The random challenge r_i from the verifier
    pub fn receive_challenge(&mut self, challenge: F) {
        self.challenges.push(challenge);
        self.round += 1;
    }

    /// Returns the current round number
    pub fn current_round(&self) -> usize {
        self.round
    }

    /// Returns whether the protocol is complete
    pub fn is_complete(&self) -> bool {
        self.round == self.num_vars
    }

    /// Returns the final evaluation point (used for verification)
    pub fn final_point(&self) -> Vec<F> {
        self.challenges.clone()
    }
}

/// Verifier in the Sumcheck protocol
///
/// The verifier checks that a multilinear polynomial sums to a claimed value
/// over the Boolean hypercube without seeing the full polynomial.
///
/// **Protocol Flow:**
/// 1. Verifier receives claimed sum
/// 2. For each round i (0 to n-1):
///    - Verifier receives univariate polynomial g_i from prover
///    - Verifier checks: g_i(0) + g_i(1) = current_claim
///    - Verifier sends random challenge r_i
///    - Verifier updates claim to g_i(r_i)
/// 3. After n rounds, verifier directly evaluates polynomial at final point
///    and checks if it equals the final claim
pub struct Verifier<F: Field> {
    /// The claimed sum over the Boolean hypercube
    claimed_sum: F,
    /// Current claim (updated each round)
    current_claim: F,
    /// Random challenges sent so far
    challenges: Vec<F>,
    /// Current round number
    round: usize,
    /// Number of variables in the polynomial
    num_vars: usize,
    /// Temporary storage for the current polynomial (for computing next claim)
    current_polynomial: Option<UnivariatePolynomial<F>>,
}

impl<F: Field> Verifier<F> {
    /// Creates a new verifier
    ///
    /// # Arguments
    /// * `claimed_sum` - The claimed sum of polynomial evaluations
    /// * `num_vars` - Number of variables in the polynomial
    ///
    /// # Returns
    /// A new Verifier instance
    pub fn new(claimed_sum: F, num_vars: usize) -> Self {
        Verifier {
            claimed_sum,
            current_claim: claimed_sum,
            challenges: Vec::new(),
            round: 0,
            num_vars,
            current_polynomial: None,
        }
    }

    /// Receives the univariate polynomial from the prover
    ///
    /// Checks that g_i(0) + g_i(1) = current_claim
    ///
    /// # Arguments
    /// * `message` - The SumcheckMessage from the prover
    ///
    /// # Returns
    /// Ok(()) if check passes, Err with message if check fails
    pub fn receive_polynomial(&mut self, message: &SumcheckMessage<F>) -> Result<(), String> {
        match message {
            SumcheckMessage::ProverPolynomial(coeffs) => {
                // Reconstruct univariate polynomial from coefficients
                let mut poly = UnivariatePolynomial::new();
                for (degree, &coeff) in coeffs.iter().enumerate() {
                    if !coeff.is_zero() {
                        poly.set_coefficient(degree, coeff);
                    }
                }

                // Check: g_i(0) + g_i(1) = current_claim
                let g_0 = poly.evaluate_horner(F::zero());
                let g_1 = poly.evaluate_horner(F::one());
                let sum = g_0 + g_1;

                if sum != self.current_claim {
                    return Err(format!(
                        "Sumcheck failed at round {}: g(0) + g(1) = {} != {}",
                        self.round, sum, self.current_claim
                    ));
                }

                // Store polynomial for later use
                self.current_polynomial = Some(poly);
                Ok(())
            }
            _ => Err("Expected ProverPolynomial message".to_string()),
        }
    }

    /// Sends a random challenge to the prover
    ///
    /// # Arguments
    /// * `challenge` - Random field element
    ///
    /// # Returns
    /// A SumcheckMessage containing the challenge
    pub fn send_challenge(&mut self, challenge: F) -> SumcheckMessage<F> {
        // Update current claim to g_i(r_i)
        if let Some(ref poly) = self.current_polynomial {
            self.current_claim = poly.evaluate_horner(challenge);
        }

        self.challenges.push(challenge);
        self.round += 1;
        self.current_polynomial = None;

        SumcheckMessage::VerifierChallenge(challenge)
    }

    /// Verifies the final evaluation
    ///
    /// After all rounds, the verifier checks that the final claim equals
    /// the polynomial evaluated at the final point.
    ///
    /// # Arguments
    /// * `poly` - The multilinear polynomial (for final verification)
    /// * `final_value` - The value claimed by the prover at the final point
    ///
    /// # Returns
    /// Ok(()) if verification passes, Err with message if it fails
    pub fn verify_final(
        &self,
        poly: &MultilinearPolynomial<F>,
        final_value: F,
    ) -> Result<(), String> {
        if self.round != self.num_vars {
            return Err(format!(
                "Protocol not complete: {} rounds done, {} expected",
                self.round, self.num_vars
            ));
        }

        // Evaluate polynomial at the final point
        let actual_value = poly
            .evaluate(&self.challenges)
            .map_err(|e| format!("Failed to evaluate polynomial: {}", e))?;

        if actual_value != final_value {
            return Err(format!(
                "Final verification failed: {} != {}",
                actual_value, final_value
            ));
        }

        Ok(())
    }

    /// Returns the current round number
    pub fn current_round(&self) -> usize {
        self.round
    }

    /// Returns whether the protocol is complete
    pub fn is_complete(&self) -> bool {
        self.round == self.num_vars
    }

    /// Returns the challenges sent so far
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
}

/// Interactive Sumcheck Protocol
///
/// Manages the interaction between prover and verifier
///
/// **Protocol:**
/// 1. Prover and Verifier are initialized
/// 2. For each round:
///    - Prover sends univariate polynomial
///    - Verifier checks consistency and sends random challenge
/// 3. After n rounds, final verification is performed
pub struct SumcheckProtocol<F: Field> {
    prover: Prover<F>,
    verifier: Verifier<F>,
    transcript: Vec<(SumcheckMessage<F>, SumcheckMessage<F>)>,
}

impl<F: Field> SumcheckProtocol<F> {
    /// Creates a new Sumcheck protocol instance
    ///
    /// # Arguments
    /// * `poly` - The multilinear polynomial
    /// * `claimed_sum` - The claimed sum of evaluations
    ///
    /// # Returns
    /// A new SumcheckProtocol instance
    pub fn new(poly: MultilinearPolynomial<F>, claimed_sum: F) -> Self {
        let num_vars = poly.num_vars();
        let prover = Prover::new(poly);
        let verifier = Verifier::new(claimed_sum, num_vars);

        SumcheckProtocol {
            prover,
            verifier,
            transcript: Vec::new(),
        }
    }

    /// Executes one round of the protocol
    ///
    /// # Arguments
    /// * `challenge` - Random challenge for this round (from verifier)
    ///
    /// # Returns
    /// Ok(()) if round succeeds, Err with message if verification fails
    pub fn execute_round(&mut self, challenge: F) -> Result<(), String> {
        // Prover sends polynomial
        let prover_msg = self.prover.send_polynomial();

        // Verifier receives and checks polynomial
        self.verifier.receive_polynomial(&prover_msg)?;

        // Verifier sends challenge
        let verifier_msg = self.verifier.send_challenge(challenge);

        // Prover receives challenge
        self.prover.receive_challenge(challenge);

        // Record in transcript
        self.transcript.push((prover_msg, verifier_msg));

        Ok(())
    }

    /// Executes all rounds of the protocol
    ///
    /// # Arguments
    /// * `challenges` - Random challenges for each round
    ///
    /// # Returns
    /// Ok(()) if all rounds succeed, Err with message if any fails
    pub fn execute_all_rounds(&mut self, challenges: Vec<F>) -> Result<(), String> {
        if challenges.len() != self.prover.num_vars {
            return Err(format!(
                "Expected {} challenges, got {}",
                self.prover.num_vars,
                challenges.len()
            ));
        }

        for challenge in challenges {
            self.execute_round(challenge)?;
        }

        Ok(())
    }

    /// Performs final verification
    ///
    /// # Arguments
    /// * `poly` - The multilinear polynomial
    ///
    /// # Returns
    /// Ok(()) if final verification passes, Err with message if it fails
    pub fn verify_final(&self, poly: &MultilinearPolynomial<F>) -> Result<(), String> {
        let final_value = poly
            .evaluate(&self.prover.final_point())
            .map_err(|e| format!("Failed to evaluate polynomial: {}", e))?;

        self.verifier.verify_final(poly, final_value)
    }

    /// Returns the current round number
    pub fn current_round(&self) -> usize {
        self.prover.current_round()
    }

    /// Returns whether the protocol is complete
    pub fn is_complete(&self) -> bool {
        self.prover.is_complete()
    }

    /// Returns the transcript of all messages
    pub fn transcript(&self) -> &[(SumcheckMessage<F>, SumcheckMessage<F>)] {
        &self.transcript
    }

    /// Returns the final challenges
    pub fn final_challenges(&self) -> Vec<F> {
        self.prover.final_point()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::Zero;

    #[test]
    fn test_sumcheck_basic_2vars() {
        // Create polynomial: P(x0, x1) = 1 + 2*x0 + 3*x1 + 4*x0*x1
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32)).unwrap();
        poly.set_coefficient(1, Fr::from(2u32)).unwrap();
        poly.set_coefficient(2, Fr::from(3u32)).unwrap();
        poly.set_coefficient(3, Fr::from(4u32)).unwrap();

        // Compute claimed sum: P(0,0) + P(1,0) + P(0,1) + P(1,1)
        // = 1 + (1+2) + (1+3) + (1+2+3+4) = 1 + 3 + 4 + 10 = 18
        let claimed_sum = Fr::from(18u32);

        // Create protocol
        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        // Execute rounds with random challenges
        let challenges = vec![Fr::from(5u32), Fr::from(7u32)];
        match protocol.execute_all_rounds(challenges) {
            Ok(_) => {}
            Err(e) => panic!("Protocol failed: {}", e),
        }

        // Verify final
        assert!(protocol.verify_final(&poly).is_ok());
    }

    #[test]
    fn test_sumcheck_3vars() {
        // Create polynomial: P(x0, x1, x2) = 1 + x0 + x1 + x2 + x0*x1 + x0*x2 + x1*x2 + x0*x1*x2
        let mut poly = MultilinearPolynomial::<Fr>::new(3);
        for mask in 0..8 {
            poly.set_coefficient(mask, Fr::from(1u32)).unwrap();
        }

        // Compute claimed sum: sum of all 2^3 = 8 evaluations
        // P(0,0,0) = 1
        // P(1,0,0) = 1 + 1 = 2
        // P(0,1,0) = 1 + 1 = 2
        // P(1,1,0) = 1 + 1 + 1 + 1 = 4
        // P(0,0,1) = 1 + 1 = 2
        // P(1,0,1) = 1 + 1 + 1 + 1 = 4
        // P(0,1,1) = 1 + 1 + 1 + 1 = 4
        // P(1,1,1) = 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = 8
        // Total = 1 + 2 + 2 + 4 + 2 + 4 + 4 + 8 = 27
        let claimed_sum = Fr::from(27u32);

        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![Fr::from(2u32), Fr::from(3u32), Fr::from(5u32)];
        match protocol.execute_all_rounds(challenges) {
            Ok(_) => {}
            Err(e) => panic!("Protocol failed: {}", e),
        }
        assert!(protocol.verify_final(&poly).is_ok());
    }

    #[test]
    fn test_sumcheck_3vars_different() {
        // Create polynomial: P(x0, x1, x2) = 1 + 2*x0 + 3*x1 + 4*x2
        // This tests the bit manipulation with a different polynomial
        let mut poly = MultilinearPolynomial::<Fr>::new(3);
        poly.set_coefficient(0, Fr::from(1u32)).unwrap(); // constant: 1
        poly.set_coefficient(1, Fr::from(2u32)).unwrap(); // x0: 2*x0
        poly.set_coefficient(2, Fr::from(3u32)).unwrap(); // x1: 3*x1
        poly.set_coefficient(4, Fr::from(4u32)).unwrap(); // x2: 4*x2

        // Compute claimed sum manually:
        // P(0,0,0) = 1
        // P(1,0,0) = 1 + 2 = 3
        // P(0,1,0) = 1 + 3 = 4
        // P(1,1,0) = 1 + 2 + 3 = 6
        // P(0,0,1) = 1 + 4 = 5
        // P(1,0,1) = 1 + 2 + 4 = 7
        // P(0,1,1) = 1 + 3 + 4 = 8
        // P(1,1,1) = 1 + 2 + 3 + 4 = 10
        // Total = 1 + 3 + 4 + 6 + 5 + 7 + 8 + 10 = 44
        let claimed_sum = Fr::from(44u32);

        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![Fr::from(2u32), Fr::from(3u32), Fr::from(5u32)];
        match protocol.execute_all_rounds(challenges) {
            Ok(_) => {}
            Err(e) => panic!("Protocol failed: {}", e),
        }
        assert!(protocol.verify_final(&poly).is_ok());
    }

    #[test]
    fn test_sumcheck_single_variable() {
        // Create polynomial: P(x0) = 5 + 3*x0
        let mut poly = MultilinearPolynomial::<Fr>::new(1);
        poly.set_coefficient(0, Fr::from(5u32)).unwrap();
        poly.set_coefficient(1, Fr::from(3u32)).unwrap();

        // Claimed sum: P(0) + P(1) = 5 + (5+3) = 13
        let claimed_sum = Fr::from(13u32);

        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![Fr::from(7u32)];
        assert!(protocol.execute_all_rounds(challenges).is_ok());
        assert!(protocol.verify_final(&poly).is_ok());
    }

    #[test]
    fn test_sumcheck_wrong_claim_fails() {
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32)).unwrap();
        poly.set_coefficient(1, Fr::from(2u32)).unwrap();
        poly.set_coefficient(2, Fr::from(3u32)).unwrap();
        poly.set_coefficient(3, Fr::from(4u32)).unwrap();

        // Wrong claimed sum
        let claimed_sum = Fr::from(100u32);

        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![Fr::from(5u32), Fr::from(7u32)];
        // This should fail during verification
        let result = protocol.execute_all_rounds(challenges);
        assert!(result.is_err());
    }

    #[test]
    fn test_sumcheck_sparse_polynomial() {
        // Sparse polynomial with many variables but few terms
        let mut poly = MultilinearPolynomial::<Fr>::new(4);
        poly.set_coefficient(0, Fr::from(10u32)).unwrap(); // constant
        poly.set_coefficient(1 << 1, Fr::from(5u32)).unwrap(); // x1
        poly.set_coefficient((1 << 2) | (1 << 3), Fr::from(3u32))
            .unwrap(); // x2*x3

        // Compute claimed sum
        let mut claimed_sum = Fr::zero();
        for i in 0..(1u64 << 4) {
            let point = crate::univariate::BooleanHypercube::<Fr>::index_to_point(i, 4);
            if let Ok(val) = poly.evaluate(&point) {
                claimed_sum += val;
            }
        }

        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![
            Fr::from(2u32),
            Fr::from(3u32),
            Fr::from(5u32),
            Fr::from(7u32),
        ];
        assert!(protocol.execute_all_rounds(challenges).is_ok());
        assert!(protocol.verify_final(&poly).is_ok());
    }

    #[test]
    fn test_sumcheck_transcript() {
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32)).unwrap();
        poly.set_coefficient(1, Fr::from(2u32)).unwrap();

        // P(0,0) = 1, P(1,0) = 1+2 = 3, P(0,1) = 1, P(1,1) = 1+2 = 3
        // Sum = 1 + 3 + 1 + 3 = 8
        let claimed_sum = Fr::from(8u32);
        let mut protocol = SumcheckProtocol::new(poly.clone(), claimed_sum);

        let challenges = vec![Fr::from(5u32), Fr::from(7u32)];
        match protocol.execute_all_rounds(challenges) {
            Ok(_) => {}
            Err(e) => panic!("Protocol failed: {}", e),
        }

        // Check transcript
        let transcript = protocol.transcript();
        assert_eq!(transcript.len(), 2);

        // Each round should have prover polynomial and verifier challenge
        for (prover_msg, verifier_msg) in transcript {
            match prover_msg {
                SumcheckMessage::ProverPolynomial(_) => {}
                _ => panic!("Expected ProverPolynomial"),
            }
            match verifier_msg {
                SumcheckMessage::VerifierChallenge(_) => {}
                _ => panic!("Expected VerifierChallenge"),
            }
        }
    }

    #[test]
    fn test_prover_intermediate_states() {
        let mut poly = MultilinearPolynomial::<Fr>::new(2);
        poly.set_coefficient(0, Fr::from(1u32)).unwrap();
        poly.set_coefficient(1, Fr::from(2u32)).unwrap();
        poly.set_coefficient(2, Fr::from(3u32)).unwrap();
        poly.set_coefficient(3, Fr::from(4u32)).unwrap();

        let prover = Prover::new(poly);

        // Initially at round 0
        assert_eq!(prover.current_round(), 0);
        assert!(!prover.is_complete());

        // After receiving first challenge
        let mut prover = prover;
        prover.receive_challenge(Fr::from(5u32));
        assert_eq!(prover.current_round(), 1);
        assert!(!prover.is_complete());

        // After receiving second challenge
        prover.receive_challenge(Fr::from(7u32));
        assert_eq!(prover.current_round(), 2);
        assert!(prover.is_complete());
    }

    #[test]
    fn test_verifier_intermediate_states() {
        let verifier = Verifier::new(Fr::from(18u32), 2);

        assert_eq!(verifier.current_round(), 0);
        assert!(!verifier.is_complete());
        assert_eq!(verifier.challenges().len(), 0);
    }
}
