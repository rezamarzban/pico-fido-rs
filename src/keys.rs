//! Key derivation and private key encryption logic:
//! Architecture: PIN + IR PIN + SRAM-PUF secret -> Argon2id -> 256-bit key -> AES-256-GCM -> Encrypted private key
//! (Default magic 10-zero PIN mechanism completely removed)

use argon2::{Argon2, Params, Version};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use zeroize::Zeroize;

pub struct KeyManager;

impl KeyManager {
    /// Derives 256-bit key from Host PIN, IR PIN, and SRAM-PUF secret via Argon2id
    pub fn derive_key(host_pin: &[u8], ir_pin: &[u8], puf_secret: &[u8]) -> [u8; 32] {
        let mut combined_input = heapless::Vec::<u8, 128>::new();
        let _ = combined_input.extend_from_slice(host_pin);
        let _ = combined_input.extend_from_slice(ir_pin);
        let _ = combined_input.extend_from_slice(puf_secret);

        let mut output_key = [0u8; 32];
        
        let params = Params::new(1922, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
        
        let _ = argon2.hash_password_into(&combined_input, b"pico_fido_argon2_salt", &mut output_key);

        combined_input.zeroize();
        output_key
    }

    /// Encrypts private key using derived 256-bit key and AES-256-GCM
    pub fn encrypt_private_key(key_bytes: &[u8; 32], private_key: &[u8], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.encrypt(nonce, private_key).map_err(|_| "Encryption error")
    }

    /// Decrypts private key using derived 256-bit key and AES-256-GCM
    pub fn decrypt_private_key(key_bytes: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption error")
    }
}
