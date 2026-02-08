// Binary exponentiation for efficient modular exponentiation
fn mod_exponentiation(base: i128, exponent: i128, modulus: i128) -> i128 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exponent = exponent;

    while exponent > 0 {
        if exponent % 2 == 1 {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    result
}

// Verify Fermat's Little Theorem
fn verify_fermat(a: i128, p: i128) -> bool {
    mod_exponentiation(a, p - 1, p) == 1
}

// Find modular inverse using FLT corollary
fn mod_inverse_flt(a: i128, p: i128) -> i128 {
    mod_exponentiation(a, p - 2, p)
}

// Example usage
fn main() {
    let a = 3;
    let p = 7;

    // Verify FLT
    println!(
        "{}^({}-1) mod {} = {}",
        a,
        p,
        p,
        mod_exponentiation(a, p - 1, p)
    );

    // Find modular inverse
    let inverse = mod_inverse_flt(a, p);
    println!("Modular inverse of {} mod {} = {}", a, p, inverse);
    println!(
        "Verification: {} X {} mod {} = {}",
        a,
        inverse,
        p,
        (a * inverse) % p
    );
}
