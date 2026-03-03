// Example demonstrating the Pedersen Commitment Scheme
//
// This example shows:
// 1. Basic commitment and verification
// 2. Homomorphic addition of commitments
// 3. Hiding property demonstration

use ark_bn254::{Fr, G1Projective};
use ark_std::test_rng;
use library::pedersen_commitment::{Opening, PedersenCommitment};

fn main() {
    println!("=== Pedersen Commitment Scheme Demo ===\n");

    let mut rng = test_rng();

    // Create a new Pedersen commitment scheme
    println!("1. Creating Pedersen commitment scheme with random generators...");
    let pc = PedersenCommitment::<G1Projective>::new(&mut rng);
    println!("Commitment scheme initialized\n");

    // Example 1: Basic commitment and verification
    println!("2. Basic Commitment and Verification:");
    let secret_value = 42u64;
    let message = Fr::from(secret_value);
    println!("Secret value: {}", secret_value);

    let (commitment, opening) = pc.commit_with_rng(message, &mut rng);
    println!("Commitment created");

    let is_valid = pc.verify(&commitment, &opening);
    println!("Verification result: {}", is_valid);
    assert!(is_valid);
    println!();

    // Example 2: Homomorphic addition
    println!("3. Homomorphic Addition:");
    let value1 = 10u64;
    let value2 = 20u64;
    println!("Value 1: {}", value1);
    println!("Value 2: {}", value2);

    let m1 = Fr::from(value1);
    let m2 = Fr::from(value2);

    let (c1, o1) = pc.commit_with_rng(m1, &mut rng);
    let (c2, o2) = pc.commit_with_rng(m2, &mut rng);
    println!("Created commitments for both values");

    // Add commitments
    let c_sum = pc.add_commitments(&c1, &c2);
    let o_sum = pc.add_openings(&o1, &o2);
    println!("Added commitments homomorphically");

    // Verify the sum
    let sum_valid = pc.verify(&c_sum, &o_sum);
    println!("Sum verification: {}", sum_valid);
    assert!(sum_valid);

    // Check that the sum is correct
    let expected_sum = Fr::from(value1 + value2);
    assert_eq!(o_sum.message, expected_sum);
    println!("Sum equals {} (correct!)\n", value1 + value2);

    // Example 3: Hiding property
    println!("4. Hiding Property Demonstration:");
    let same_value = Fr::from(100u64);
    println!("Committing to the same value twice with different randomness...");

    let (commit1, _) = pc.commit_with_rng(same_value, &mut rng);
    let (commit2, _) = pc.commit_with_rng(same_value, &mut rng);

    let commitments_different = commit1.value != commit2.value;
    println!("Commitments are different: {}", commitments_different);
    println!("This demonstrates the hiding property - same value produces");
    println!("different commitments due to random blinding factors.\n");

    // Example 4: Binding property
    println!("5. Binding Property Demonstration:");
    let original_value = Fr::from(50u64);
    let fake_value = Fr::from(51u64);

    let (commitment, opening) = pc.commit_with_rng(original_value, &mut rng);
    println!("Created commitment to value: 50");

    // Try to open with a different value
    let fake_opening = Opening {
        message: fake_value,
        randomness: opening.randomness,
    };

    let fake_valid = pc.verify(&commitment, &fake_opening);
    println!(
        "Attempting to open with different value (51): {}",
        fake_valid
    );
}
