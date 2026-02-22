use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
};

pub fn aes(message: &str, key: &[u8]) -> bool {
    let key = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = match cipher.encrypt(&nonce, message.as_ref()) {
        Ok(ct) => ct,
        Err(_) => return false,
    };

    let plaintext = match cipher.decrypt(&nonce, ciphertext.as_ref()) {
        Ok(pt) => pt,
        Err(_) => return false,
    };

    plaintext == message.as_bytes()
}
