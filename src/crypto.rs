use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

// Argon2id KDF parameters, pinned explicitly rather than via `Argon2::default()`
// so that a future `argon2` crate upgrade which changes the library defaults
// cannot silently alter the derived key and lock users out of their vaults.
// These values match the argon2 0.5.x defaults, so existing vaults stay
// decryptable. Changing any of them requires a migration that re-derives every
// vault key (see `kf passwd` / `reencrypt_all`).
const ARGON2_M_COST: u32 = 19_456; // memory, in KiB (19 MiB)
const ARGON2_T_COST: u32 = 2; // iterations
const ARGON2_P_COST: u32 = 1; // parallelism

pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(passphrase: &str, salt: &[u8]) -> Result<Self> {
        let mut key_bytes = [0u8; KEY_LEN];
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes[..]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN {
            bail!("Invalid encrypted data: too short");
        }
        let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
        let ciphertext = &data[NONCE_LEN..];
        self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!(
                "Decryption failed: wrong passphrase, or the data is corrupted or tampered with"
            )
        })
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 32];
        rand::rng().fill(&mut salt[..]);
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crypto() -> Crypto {
        let salt = Crypto::generate_salt();
        Crypto::new("test-passphrase-123", &salt).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = make_crypto();
        let plaintext = b"hello world, this is a secret API key sk-abc123def456";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_unique_nonces() {
        let crypto = make_crypto();
        let plaintext = b"same plaintext";
        let ct1 = crypto.encrypt(plaintext).unwrap();
        let ct2 = crypto.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertexts even for same plaintext
        assert_ne!(ct1, ct2);
        // Both decrypt to the same value
        assert_eq!(crypto.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(crypto.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_passphrase_fails() {
        let salt = Crypto::generate_salt();
        let crypto = Crypto::new("correct-passphrase", &salt).unwrap();
        let crypto_wrong = Crypto::new("wrong-passphrase", &salt).unwrap();
        let plaintext = b"sensitive data";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        assert!(crypto_wrong.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decrypt_empty_data_fails() {
        let crypto = make_crypto();
        assert!(crypto.decrypt(&[]).is_err());
    }

    #[test]
    fn decrypt_too_short_data_fails() {
        let crypto = make_crypto();
        // Less than 12 bytes (nonce length)
        assert!(crypto.decrypt(&[0; 11]).is_err());
        assert!(crypto.decrypt(&[0; 5]).is_err());
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let crypto = make_crypto();
        let plaintext = b"test data";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        // Truncate ciphertext portion (keep nonce only)
        let truncated = &encrypted[..NONCE_LEN];
        assert!(crypto.decrypt(truncated).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let crypto = make_crypto();
        let mut encrypted = crypto.encrypt(b"important secret value").unwrap();
        // Flip a bit in the ciphertext body (past the nonce) — AES-GCM's
        // authentication tag must reject the modified data.
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(crypto.decrypt(&encrypted).is_err());
    }

    #[test]
    fn encrypt_empty_plaintext_works() {
        let crypto = make_crypto();
        let encrypted = crypto.encrypt(b"").unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_plaintext_works() {
        let crypto = make_crypto();
        let plaintext = vec![0x42u8; 10_000];
        let encrypted = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn generate_salt_produces_unique_salts() {
        let s1 = Crypto::generate_salt();
        let s2 = Crypto::generate_salt();
        assert_eq!(s1.len(), 32);
        assert_eq!(s2.len(), 32);
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_passphrases_produce_different_results() {
        let salt = Crypto::generate_salt();
        let crypto1 = Crypto::new("passphrase-A", &salt).unwrap();
        let crypto2 = Crypto::new("passphrase-B", &salt).unwrap();
        let plaintext = b"same secret";
        let enc1 = crypto1.encrypt(plaintext).unwrap();
        let enc2 = crypto2.encrypt(plaintext).unwrap();
        // Decrypting enc1 with crypto2 should fail
        assert!(crypto2.decrypt(&enc1).is_err());
        assert!(crypto1.decrypt(&enc2).is_err());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let crypto1 = Crypto::new("same-passphrase", &Crypto::generate_salt()).unwrap();
        let crypto2 = Crypto::new("same-passphrase", &Crypto::generate_salt()).unwrap();
        let plaintext = b"test";
        let enc1 = crypto1.encrypt(plaintext).unwrap();
        // crypto2 cannot decrypt crypto1's ciphertext (different salt → different key)
        assert!(crypto2.decrypt(&enc1).is_err());
    }
}
