// Extended Euclidean Algorithm to find modular inverse
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    (gcd, x, y)
}

// Find modular multiplicative inverse
fn mod_inverse(a: i128, m: i128) -> Result<i128, String> {
    let (gcd, x, _) = extended_gcd(a, m);
    if gcd != 1 {
        return Err(format!("Modular inverse does not exist for this"));
    }
    Ok((x % m + m) % m)
}

// Chinese Remainder Theorem solver
fn chinese_remainder_theorem(remainders: &[i128], moduli: &[i128]) -> Result<i128, String> {
    if remainders.len() != moduli.len() {
        return Err("Remainders and moduli must have the same length".to_string());
    }

    let n = remainders.len();

    // Calculate M (product of all moduli)
    let m: i128 = moduli.iter().product();

    let mut result = 0;

    for i in 0..n {
        // Calculate Mᵢ = M / mᵢ
        let mi = m / moduli[i];

        // Find modular inverse yᵢ
        let yi = mod_inverse(mi, moduli[i])?;

        // Add to result
        result += remainders[i] * mi * yi;
    }

    // Return result modulo M
    Ok(result % m)
}

// Example usage
fn main() {
    // for a system of equations with no solution
    let remainders = vec![13, 17, 14];
    let moduli = vec![7, 76, 91];

    printing_solution(&remainders, &moduli);

    // for a system of equations with a solution
    let remainders2 = vec![2, 3, 2];
    let moduli2 = vec![3, 5, 7];
    printing_solution(&remainders2, &moduli2);
}
fn printing_solution(remainders2: &[i128], moduli2: &[i128]) {
    match chinese_remainder_theorem(&remainders2, &moduli2) {
        Ok(solution) => {
            println!("Solution: x = {}", solution);

            // Verify the solution
            for i in 0..remainders2.len() {
                println!("x mod {} = {}", moduli2[i], solution % moduli2[i]);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
