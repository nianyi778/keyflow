use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Result};
use rand::RngCore;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(passphrase: &str, salt: &[u8]) -> Result<Self> {
        let mut key_bytes = [0u8; KEY_LEN];
        argon2::Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    /// Create a Crypto instance from a raw 32-byte key (no KDF).
    /// Used for session encryption where the key is machine-derived.
    pub fn new_from_raw_key(raw_key: &[u8; KEY_LEN]) -> Result<Self> {
        let key = Key::<Aes256Gcm>::from_slice(raw_key);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
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
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed (wrong passphrase?): {}", e))
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }
}
