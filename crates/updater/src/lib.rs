// Secure Auto-Update: reuses safeprompt-integrity's Ed25519 signing (a
// SignedManifest already pins {version, binary_sha256}) rather than a
// fourth signing setup — auto-update needs exactly the same guarantee
// integrity manifests already provide ("this is the vendor's actual
// binary"), just fetched over the network instead of checked once at
// startup.
//
// Architectural note on WHY this belongs in the watchdog, not the service
// updating itself: a running Windows (or Linux) process generally can't
// safely replace its own executable file while executing from that image.
// The watchdog supervises the service as a *child* process — once the
// child has exited, nothing holds its exe file open, so the watchdog (a
// different process, a different file) can safely replace it before
// restarting. The watchdog's own binary is deliberately NOT self-updating
// in this pass — a separate, harder problem, stated as a limitation here
// rather than silently glossed over.

use safeprompt_integrity::{hash_bytes, IntegrityError, ManifestVerifier, SignedManifest};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("network request failed: {0}")]
    Network(String),
    #[error("file operation failed: {0}")]
    Io(String),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("downloaded binary does not match the signed manifest")]
    BinaryMismatch,
}

pub struct Updater {
    verifier: ManifestVerifier,
    client: reqwest::Client,
}

impl Updater {
    pub fn new(verifier: ManifestVerifier) -> Self {
        Self {
            verifier,
            client: reqwest::Client::new(),
        }
    }

    /// Fetches the manifest at `manifest_url` and verifies its signature.
    /// Returns `Ok(None)` — not an error — if its version isn't newer than
    /// `current_version` (this is the expected result of most checks, not
    /// a failure), so callers can poll this on a timer without treating
    /// "nothing to do" as an error case.
    pub async fn check_for_update(&self, manifest_url: &str, current_version: &str) -> Result<Option<SignedManifest>, UpdateError> {
        let response = self
            .client
            .get(manifest_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        let signed: SignedManifest = response.json().await.map_err(|e| UpdateError::Network(e.to_string()))?;

        self.verifier.verify_signature(&signed)?;

        if !is_newer_version(&signed.manifest.version, current_version) {
            return Ok(None);
        }
        Ok(Some(signed))
    }

    /// Downloads the binary from `binary_url` and verifies its hash matches
    /// the (already signature-verified) manifest — catches a corrupted or
    /// tampered-in-transit download before it's ever applied.
    pub async fn download_and_verify(&self, binary_url: &str, signed: &SignedManifest) -> Result<Vec<u8>, UpdateError> {
        let response = self
            .client
            .get(binary_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        let bytes = response.bytes().await.map_err(|e| UpdateError::Network(e.to_string()))?;

        if hash_bytes(&bytes) != signed.manifest.binary_sha256 {
            return Err(UpdateError::BinaryMismatch);
        }
        Ok(bytes.to_vec())
    }

    /// Atomically replaces the file at `target_path` with `new_binary`.
    /// Never call this to replace the *currently executing* binary of the
    /// calling process — see the module doc comment.
    pub fn apply_update(&self, target_path: &Path, new_binary: &[u8]) -> Result<(), UpdateError> {
        let tmp_path = target_path.with_extension("update-tmp");
        std::fs::write(&tmp_path, new_binary).map_err(|e| UpdateError::Io(format!("writing {}: {e}", tmp_path.display())))?;
        std::fs::rename(&tmp_path, target_path).map_err(|e| UpdateError::Io(format!("replacing {}: {e}", target_path.display())))?;
        Ok(())
    }
}

/// Lightweight dotted-version comparison — not full semver (no pre-release/
/// build-metadata handling), sufficient for straightforward "1.2.3"-style
/// release versions, and correctly handles "1.10.0" > "1.9.0" unlike a
/// naive string comparison.
fn is_newer_version(candidate: &str, current: &str) -> bool {
    parse_version(candidate) > parse_version(current)
}

fn parse_version(v: &str) -> Vec<u64> {
    v.split('.').map(|part| part.parse::<u64>().unwrap_or(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use ed25519_dalek::SigningKey;
    use safeprompt_integrity::{IntegrityManifest, ManifestIssuer};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn issuer_and_verifier() -> (ManifestIssuer, ManifestVerifier) {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let issuer = ManifestIssuer::from_secret_key_bytes(&signing_key.to_bytes());
        let verifier = ManifestVerifier::new(issuer.verifying_key());
        (issuer, verifier)
    }

    fn manifest_for(version: &str, binary: &[u8]) -> IntegrityManifest {
        IntegrityManifest {
            version: version.to_string(),
            binary_sha256: hash_bytes(binary),
            policy_sha256: None,
            expected_signer_thumbprint: None,
            issued_at: chrono::Utc::now(),
        }
    }

    /// Mock update server: serves a fixed signed manifest at `/manifest`
    /// and fixed binary bytes at `/binary`.
    async fn spawn_mock_update_server(signed: SignedManifest, binary: Vec<u8>) -> SocketAddr {
        let signed = Arc::new(signed);
        let binary = Arc::new(binary);
        let app = Router::new()
            .route(
                "/manifest",
                get({
                    let signed = Arc::clone(&signed);
                    move || {
                        let signed = Arc::clone(&signed);
                        async move { axum::Json((*signed).clone()) }
                    }
                }),
            )
            .route(
                "/binary",
                get({
                    let binary = Arc::clone(&binary);
                    move || {
                        let binary = Arc::clone(&binary);
                        async move { (*binary).clone() }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn detects_a_newer_version_available() {
        let binary = b"new binary contents v2".to_vec();
        let (issuer, verifier) = issuer_and_verifier();
        let signed = issuer.issue(manifest_for("1.2.0", &binary)).unwrap();
        let addr = spawn_mock_update_server(signed, binary).await;

        let updater = Updater::new(verifier);
        let result = updater
            .check_for_update(&format!("http://{addr}/manifest"), "1.1.0")
            .await
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().manifest.version, "1.2.0");
    }

    #[tokio::test]
    async fn reports_no_update_when_already_current() {
        let binary = b"same version".to_vec();
        let (issuer, verifier) = issuer_and_verifier();
        let signed = issuer.issue(manifest_for("1.2.0", &binary)).unwrap();
        let addr = spawn_mock_update_server(signed, binary).await;

        let updater = Updater::new(verifier);
        let result = updater
            .check_for_update(&format!("http://{addr}/manifest"), "1.2.0")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn refuses_to_downgrade_to_an_older_version() {
        let binary = b"an old build".to_vec();
        let (issuer, verifier) = issuer_and_verifier();
        let signed = issuer.issue(manifest_for("1.0.0", &binary)).unwrap();
        let addr = spawn_mock_update_server(signed, binary).await;

        let updater = Updater::new(verifier);
        let result = updater
            .check_for_update(&format!("http://{addr}/manifest"), "1.5.0")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn rejects_a_manifest_signed_by_a_different_key() {
        let binary = b"forged build".to_vec();
        let (attacker_issuer, _real_verifier) = issuer_and_verifier();
        let (_real_issuer, real_verifier) = issuer_and_verifier();
        let forged = attacker_issuer.issue(manifest_for("9.9.9", &binary)).unwrap();
        let addr = spawn_mock_update_server(forged, binary).await;

        let updater = Updater::new(real_verifier);
        let result = updater.check_for_update(&format!("http://{addr}/manifest"), "1.0.0").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn downloads_and_verifies_a_matching_binary() {
        let binary = b"the real new binary".to_vec();
        let (issuer, verifier) = issuer_and_verifier();
        let signed = issuer.issue(manifest_for("2.0.0", &binary)).unwrap();
        let addr = spawn_mock_update_server(signed.clone(), binary.clone()).await;

        let updater = Updater::new(verifier);
        let downloaded = updater
            .download_and_verify(&format!("http://{addr}/binary"), &signed)
            .await
            .unwrap();

        assert_eq!(downloaded, binary);
    }

    #[tokio::test]
    async fn rejects_a_download_that_does_not_match_the_manifest_hash() {
        let manifest_binary = b"what the manifest says".to_vec();
        let served_binary = b"something different got served".to_vec();
        let (issuer, verifier) = issuer_and_verifier();
        let signed = issuer.issue(manifest_for("2.0.0", &manifest_binary)).unwrap();
        let addr = spawn_mock_update_server(signed.clone(), served_binary).await;

        let updater = Updater::new(verifier);
        let result = updater.download_and_verify(&format!("http://{addr}/binary"), &signed).await;

        assert!(matches!(result, Err(UpdateError::BinaryMismatch)));
    }

    #[test]
    fn apply_update_replaces_file_contents_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("safeprompt-service.exe");
        std::fs::write(&target, b"old version").unwrap();

        let (_issuer, verifier) = issuer_and_verifier();
        let updater = Updater::new(verifier);
        updater.apply_update(&target, b"new version").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new version");
    }

    #[test]
    fn dotted_version_comparison_handles_multi_digit_segments_correctly() {
        assert!(is_newer_version("1.10.0", "1.9.0"), "1.10.0 must be newer than 1.9.0, not less (naive string compare would get this wrong)");
        assert!(!is_newer_version("1.9.0", "1.10.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
    }
}
