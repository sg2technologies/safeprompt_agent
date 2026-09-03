// Agent tamper protection, part 1: binary + policy integrity verification.
// A signed manifest pins the expected SHA256 of the Agent binary (and,
// optionally, its policy file); the Agent refuses to run if what's actually
// on disk doesn't match what the vendor signed. Same Ed25519 pattern as
// `safeprompt-licensing`, deliberately a separate crate/keypair concern —
// licensing answers "is this customer entitled to run," integrity answers
// "is this the binary/policy the vendor actually shipped."
//
// Honest scope note: this is process-startup integrity verification, not
// kernel-level tamper resistance. It detects a modified binary/policy file
// and refuses to start; it does not stop a local admin from patching the
// binary *and* re-signing a manifest with their own key (that requires the
// OS to refuse untrusted code signatures, e.g. Windows code integrity
// policies — out of scope here), nor does it run as a protected process.
// See `safeprompt-watchdog` for the separate "keep the service running"
// concern (process supervision, not integrity).

pub mod authenticode;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub version: String,
    pub binary_sha256: String,
    pub policy_sha256: Option<String>,
    /// Authenticode certificate thumbprint (uppercase hex SHA1) the binary
    /// is expected to be signed by, checked in addition to the hash pin
    /// above when present. Pinning matters here specifically because it's
    /// carried *inside the signed manifest* — an unprotected env var or
    /// config value naming an "expected signer" would let a local attacker
    /// just point it at their own forged certificate's thumbprint, defeating
    /// the check entirely. `#[serde(default)]` so older manifests without
    /// this field still parse; `None` means the signer isn't checked at
    /// all, same graceful-degradation-if-unconfigured posture as everything
    /// else in this codebase.
    #[serde(default)]
    pub expected_signer_thumbprint: Option<String>,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: IntegrityManifest,
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrityError {
    #[error("integrity manifest signature is invalid — it was tampered with or signed by a different key")]
    BadSignature,
    #[error("running binary does not match the signed manifest — the binary may have been tampered with")]
    BinaryHashMismatch,
    #[error("policy file does not match the signed manifest — the policy may have been tampered with")]
    PolicyHashMismatch,
    #[error("Authenticode signature check failed: {0}")]
    AuthenticodeFailure(String),
    #[error("could not read file: {0}")]
    Io(String),
    #[error("malformed manifest: {0}")]
    Malformed(String),
}

pub fn hash_file(path: &Path) -> Result<String, IntegrityError> {
    let bytes = std::fs::read(path).map_err(|e| IntegrityError::Io(format!("{}: {e}", path.display())))?;
    Ok(hash_bytes(&bytes))
}

/// Same hash `hash_file` computes, for bytes already in memory (e.g. a
/// downloaded update payload not yet written to disk) rather than a file.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn canonical_bytes(manifest: &IntegrityManifest) -> Result<Vec<u8>, IntegrityError> {
    serde_json::to_vec(manifest).map_err(|e| IntegrityError::Malformed(e.to_string()))
}

pub struct ManifestIssuer {
    signing_key: SigningKey,
}

impl ManifestIssuer {
    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    pub fn issue(&self, manifest: IntegrityManifest) -> Result<SignedManifest, IntegrityError> {
        let payload = canonical_bytes(&manifest)?;
        let signature: Signature = self.signing_key.sign(&payload);
        Ok(SignedManifest {
            manifest,
            signature: BASE64.encode(signature.to_bytes()),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

pub struct ManifestVerifier {
    verifying_key: VerifyingKey,
}

impl ManifestVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, IntegrityError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|e| IntegrityError::Malformed(format!("bad public key: {e}")))?;
        Ok(Self::new(key))
    }

    /// Verifies just the signature — no binary/policy comparison. Used
    /// before a binary has even been downloaded (e.g. deciding whether an
    /// update manifest is trustworthy before spending bandwidth fetching
    /// the payload it describes); `verify_binary_at`/
    /// `verify_binary_and_policy_at` call this internally too.
    pub fn verify_signature(&self, signed: &SignedManifest) -> Result<(), IntegrityError> {
        self.check_signature(signed)
    }

    fn check_signature(&self, signed: &SignedManifest) -> Result<(), IntegrityError> {
        let payload = canonical_bytes(&signed.manifest)?;
        let sig_bytes: [u8; 64] = BASE64
            .decode(&signed.signature)
            .map_err(|e| IntegrityError::Malformed(format!("bad signature encoding: {e}")))?
            .try_into()
            .map_err(|_| IntegrityError::Malformed("signature is not 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);
        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| IntegrityError::BadSignature)
    }

    /// Verifies the manifest's signature, that `binary_path` hashes to
    /// exactly what the manifest pins, and — if the manifest pins one — that
    /// `binary_path` carries a valid Authenticode signature from the
    /// expected signing certificate. Takes the path explicitly (rather than
    /// reading `std::env::current_exe()` itself) so it's testable against
    /// arbitrary files — see [`verify_self`] for the real-usage convenience
    /// wrapper.
    pub fn verify_binary_at(&self, signed: &SignedManifest, binary_path: &Path) -> Result<(), IntegrityError> {
        self.check_signature(signed)?;
        let actual = hash_file(binary_path)?;
        if actual != signed.manifest.binary_sha256 {
            return Err(IntegrityError::BinaryHashMismatch);
        }
        if let Some(expected_thumbprint) = &signed.manifest.expected_signer_thumbprint {
            authenticode::verify_signer(binary_path, expected_thumbprint)
                .map_err(|e| IntegrityError::AuthenticodeFailure(e.to_string()))?;
        }
        Ok(())
    }

    /// Same as [`Self::verify_binary_at`], plus checks `policy_path` against
    /// `manifest.policy_sha256` if the manifest pins one. If the manifest
    /// doesn't pin a policy hash, the policy file isn't checked at all.
    pub fn verify_binary_and_policy_at(
        &self,
        signed: &SignedManifest,
        binary_path: &Path,
        policy_path: &Path,
    ) -> Result<(), IntegrityError> {
        self.verify_binary_at(signed, binary_path)?;
        if let Some(expected) = &signed.manifest.policy_sha256 {
            let actual = hash_file(policy_path)?;
            if actual != *expected {
                return Err(IntegrityError::PolicyHashMismatch);
            }
        }
        Ok(())
    }
}

/// Convenience wrapper for the Agent's own startup check: verifies the
/// currently-running executable against the manifest.
pub fn verify_self(verifier: &ManifestVerifier, signed: &SignedManifest) -> Result<(), IntegrityError> {
    let exe_path = std::env::current_exe().map_err(|e| IntegrityError::Io(e.to_string()))?;
    verifier.verify_binary_at(signed, &exe_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file.flush().unwrap();
        file
    }

    fn issuer_and_verifier() -> (ManifestIssuer, ManifestVerifier) {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let issuer = ManifestIssuer::from_secret_key_bytes(&signing_key.to_bytes());
        let verifier = ManifestVerifier::new(issuer.verifying_key());
        (issuer, verifier)
    }

    #[test]
    fn issues_and_verifies_a_matching_binary() {
        let binary = write_temp_file(b"pretend this is the agent executable");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        assert!(verifier.verify_binary_at(&signed, binary.path()).is_ok());
    }

    #[test]
    fn rejects_a_binary_that_was_modified_after_signing() {
        let binary = write_temp_file(b"original contents");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        // Simulate tampering: the file on disk changes after the manifest was signed.
        std::fs::write(binary.path(), b"TAMPERED BINARY CONTENTS").unwrap();

        assert_eq!(verifier.verify_binary_at(&signed, binary.path()), Err(IntegrityError::BinaryHashMismatch));
    }

    #[test]
    fn rejects_a_manifest_tampered_with_after_signing() {
        let binary = write_temp_file(b"contents");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let mut signed = issuer.issue(manifest).unwrap();
        signed.manifest.version = "9.9.9".to_string(); // tamper after signing

        assert_eq!(verifier.verify_binary_at(&signed, binary.path()), Err(IntegrityError::BadSignature));
    }

    #[test]
    fn rejects_a_manifest_signed_by_a_different_key() {
        let binary = write_temp_file(b"contents");
        let (_issuer, verifier) = issuer_and_verifier();
        let (attacker_issuer, _) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let forged = attacker_issuer.issue(manifest).unwrap();

        assert_eq!(verifier.verify_binary_at(&forged, binary.path()), Err(IntegrityError::BadSignature));
    }

    #[test]
    fn checks_policy_hash_when_manifest_pins_one() {
        let binary = write_temp_file(b"binary contents");
        let policy = write_temp_file(b"policy contents");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: Some(hash_file(policy.path()).unwrap()),
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        assert!(verifier.verify_binary_and_policy_at(&signed, binary.path(), policy.path()).is_ok());

        std::fs::write(policy.path(), b"TAMPERED POLICY").unwrap();
        assert_eq!(
            verifier.verify_binary_and_policy_at(&signed, binary.path(), policy.path()),
            Err(IntegrityError::PolicyHashMismatch)
        );
    }

    #[test]
    fn hash_bytes_matches_hash_file_for_the_same_content() {
        let file = write_temp_file(b"identical content");
        assert_eq!(hash_file(file.path()).unwrap(), hash_bytes(b"identical content"));
    }

    #[test]
    fn verify_signature_accepts_a_valid_manifest_without_needing_a_binary_on_disk() {
        let (issuer, verifier) = issuer_and_verifier();
        let manifest = IntegrityManifest {
            version: "1.2.0".to_string(),
            binary_sha256: "doesn't matter yet".to_string(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();
        assert!(verifier.verify_signature(&signed).is_ok());
    }

    #[test]
    fn skips_policy_check_when_manifest_does_not_pin_one() {
        let binary = write_temp_file(b"binary contents");
        let policy = write_temp_file(b"anything at all");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        assert!(verifier.verify_binary_and_policy_at(&signed, binary.path(), policy.path()).is_ok());
    }

    #[test]
    fn rejects_a_binary_that_is_not_authenticode_signed_when_a_signer_is_pinned() {
        // The positive case (a real Authenticode-signed binary from the
        // expected certificate) needs a real trusted signing certificate on
        // the test machine -- that's what
        // agent/scripts/test-authenticode-verification.ps1 proves live
        // against the actual service/watchdog binaries. This is the part
        // provable without one: a manifest that pins a signer must reject a
        // binary with no Authenticode signature at all, not silently accept
        // it just because the hash matched.
        let binary = write_temp_file(b"a plain file, never Authenticode-signed");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: Some("AABBCCDDEEFF00112233445566778899AABBCCDD".to_string()),
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        assert!(matches!(
            verifier.verify_binary_at(&signed, binary.path()),
            Err(IntegrityError::AuthenticodeFailure(_))
        ));
    }

    #[test]
    fn skips_signer_check_entirely_when_manifest_does_not_pin_one() {
        // A binary hash match with no pinned signer at all must still pass
        // -- confirms the new check is purely additive/opt-in and doesn't
        // change behavior for every manifest issued before this existed.
        let binary = write_temp_file(b"binary contents, unsigned, no signer pinned");
        let (issuer, verifier) = issuer_and_verifier();

        let manifest = IntegrityManifest {
            version: "0.1.0".to_string(),
            binary_sha256: hash_file(binary.path()).unwrap(),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: Utc::now(),
        };
        let signed = issuer.issue(manifest).unwrap();

        assert!(verifier.verify_binary_at(&signed, binary.path()).is_ok());
    }
}
