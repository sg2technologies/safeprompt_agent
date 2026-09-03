// Encrypted-at-rest storage for the root CA's private key, so the same CA
// (and thus the same OS/browser trust) survives a service restart — closes
// the gap noted in the parent module's doc comment and in
// docs/SafeGateway-Architecture-Review.md. Matches the Python original's
// *intent* (Fernet-encrypted key at rest, see [[tls-interception-architecture]]
// memory) using AES-256-GCM instead — a key derived by SHA256-hashing a
// deployment secret, not a full KDF like Argon2. That's a reasonable
// simplification given the secret is expected to come from a proper secrets
// manager / env var (already high-entropy), not a human-chosen passphrase —
// worth revisiting if this secret is ever end-user-chosen.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::Path;

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
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong secret, or the file was tampered with"))
}

pub fn save_encrypted_key(path: &Path, key_der: &[u8], secret: &str) -> anyhow::Result<()> {
    let encoded = encrypt(key_der, secret)?;
    std::fs::write(path, encoded)?;
    Ok(())
}

pub fn load_encrypted_key(path: &Path, secret: &str) -> anyhow::Result<Vec<u8>> {
    let encoded = std::fs::read_to_string(path)?;
    decrypt(&encoded, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use rcgen::KeyPair;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let plaintext = b"pretend this is a PKCS8 private key";
        let encoded = encrypt(plaintext, "correct-secret").unwrap();
        let decrypted = decrypt(&encoded, "correct-secret").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_the_wrong_secret() {
        let encoded = encrypt(b"secret key material", "correct-secret").unwrap();
        assert!(decrypt(&encoded, "wrong-secret").is_err());
    }

    #[test]
    fn decrypt_fails_if_the_ciphertext_was_tampered_with() {
        let encoded = encrypt(b"secret key material", "correct-secret").unwrap();
        let mut blob = BASE64.decode(encoded.trim()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip bits in the ciphertext/tag
        let tampered = BASE64.encode(blob);
        assert!(decrypt(&tampered, "correct-secret").is_err());
    }

    #[test]
    fn save_and_load_key_file_survives_a_simulated_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ca_signing_key.enc");

        let original = CertificateAuthority::generate().unwrap();
        save_encrypted_key(&key_path, &original.key_pair_der(), "deployment-secret").unwrap();

        let loaded_der = load_encrypted_key(&key_path, "deployment-secret").unwrap();
        let reloaded_key_pair = KeyPair::try_from(loaded_der).unwrap();
        let reloaded = CertificateAuthority::from_key_pair(reloaded_key_pair).unwrap();

        // Issuing still works with the reloaded key — the CA "survived the restart."
        let (_leaf_der, _leaf_key) = reloaded.issue_leaf_cert("chatgpt.com").unwrap();
    }

    #[test]
    fn loading_with_the_wrong_secret_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ca_signing_key.enc");

        let original = CertificateAuthority::generate().unwrap();
        save_encrypted_key(&key_path, &original.key_pair_der(), "correct-secret").unwrap();

        assert!(load_encrypted_key(&key_path, "wrong-secret").is_err());
    }
}
