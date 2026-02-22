fn main() {}
pub fn mod_exp(base: i128, exponent: i128, modulus: i128) -> i128 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exponent = exponent;

    while exponent > 0 {
        if exponent % 2 == 1 {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = base * base % modulus;
    }

    result
}
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    (gcd, x, y)
}
fn mod_inverse(a: i128, m: i128) -> Result<i128, String> {
    let (gcd, x, _) = extended_gcd(a, m);
    if gcd != 1 {
        return Err(format!("Modular inverse does not exist for this"));
    }
    Ok((x % m + m) % m)
}

pub fn rsa(p: i128, q: i128, e: i128, m: i128) -> Result<i128, String> {
    let n = p * q;
    let phi = (p - 1) * (q - 1);

    // Verify that e and phi are coprime
    let (gcd, _, _) = extended_gcd(e, phi);
    if gcd != 1 {
        return Err(format!("e and phi must be coprime"));
    }

    // Compute the ciphertext: c = m^e mod n
    let ciphertext = mod_exp(m, e, n);
    Ok(ciphertext)
}
