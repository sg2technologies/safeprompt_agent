// Same AES-256-GCM-with-hashed-secret pattern as
// agent/crates/connect_proxy/src/ca/persistence.rs — duplicated rather
// than shared across crates for ~30 lines, to avoid coupling this crate to
// connect_proxy's much larger, unrelated dependency surface (TLS, rcgen).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 12;

fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

pub fn encrypt(plaintext: &[u8], secret: &str) -> anyhow::Result<String> {
    let key_bytes = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| anyhow::anyhow!("bad key: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(blob))
}

pub fn decrypt(encoded: &str, secret: &str) -> anyhow::Result<Vec<u8>> {
    let blob = BASE64.decode(encoded.trim())?;
    if blob.len() < NONCE_LEN {
        return Err(anyhow::anyhow!("encrypted blob is shorter than one nonce — corrupted?"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);

    let key_bytes = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| anyhow::anyhow!("bad key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong secret, or the row was tampered with"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let encoded = encrypt(b"finding snippet fragment", "secret").unwrap();
        assert_eq!(decrypt(&encoded, "secret").unwrap(), b"finding snippet fragment");
    }

    #[test]
    fn decrypt_fails_with_wrong_secret() {
        let encoded = encrypt(b"data", "correct").unwrap();
        assert!(decrypt(&encoded, "wrong").is_err());
    }
}
