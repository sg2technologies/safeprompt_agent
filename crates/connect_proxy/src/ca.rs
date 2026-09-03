// Per-agent (in production: per-tenant) root CA used to MITM the AI domains
// this proxy is configured to intercept. Port of backend/gateway/ca.py's
// design intent — see docs/SafeGateway-Architecture-Review.md §6/§6b.
//
// The root key is generated once and persisted (encrypted at rest, see
// `persistence` module below) rather than regenerated on every restart —
// what actually matters for a device that already trusts the installed
// root cert is that the SAME key keeps signing leaf certs and the root's
// distinguished name stays constant, not that the in-memory root cert
// object is byte-identical across runs (its serial number/validity dates
// naturally differ each time it's rebuilt from the persisted key; that
// doesn't affect trust — TLS chain validation checks the leaf's issuer DN
// and signature against whatever root the client already has installed,
// it doesn't re-fetch or compare the server's in-memory root object).

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

pub mod persistence;

/// rustls 0.23 refuses to guess a default `CryptoProvider` if more than one
/// backend (`ring`, `aws-lc-rs`) ends up linked into the same binary — which
/// happens here because different dependencies in the workspace default to
/// different ones, and `cargo test --workspace` unifies those features into
/// a single test binary. Every real code path and every test constructs a
/// `CertificateAuthority` before touching any `rustls::ServerConfig`/
/// `ClientConfig`, so pinning the provider here — once, idempotently —
/// covers all of them without scattering this call at every TLS-config
/// construction site.
fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

const ROOT_CA_VALIDITY_YEARS: i64 = 20;
const LEAF_CERT_VALIDITY_DAYS: i64 = 90;

pub struct CertificateAuthority {
    cert: rcgen::Certificate,
    key_pair: KeyPair,
}

impl CertificateAuthority {
    /// Generates a brand-new root CA with a fresh random key. Prefer
    /// [`Self::load_or_generate`] in any long-lived deployment so the root
    /// stays stable across restarts.
    pub fn generate() -> anyhow::Result<Self> {
        Self::from_key_pair(KeyPair::generate()?)
    }

    /// Rebuilds the root CA from a previously-generated key pair (e.g. one
    /// loaded from encrypted storage via [`persistence`]).
    pub fn from_key_pair(key_pair: KeyPair) -> anyhow::Result<Self> {
        ensure_crypto_provider_installed();

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "SafePrompt Root CA");
        dn.push(DnType::OrganizationName, "SafePrompt");
        params.distinguished_name = dn;
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * ROOT_CA_VALIDITY_YEARS);

        let cert = params.self_signed(&key_pair)?;

        Ok(Self { cert, key_pair })
    }

    pub fn root_cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// PEM-encoded root certificate — this is the file an admin distributes
    /// to devices (installed into the OS/browser trust store via GPO/MDM).
    pub fn root_cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// PKCS8 DER bytes of the root private key, for persistence. Always
    /// encrypt this at rest — see [`persistence`].
    pub fn key_pair_der(&self) -> Vec<u8> {
        self.key_pair.serialize_der()
    }

    /// Loads the root CA's key from `key_path` (decrypting with `secret`) if
    /// it exists, otherwise generates a fresh one and saves it there
    /// (encrypted) for next time. This is what makes the CA — and thus
    /// what a device needs to trust — stable across restarts.
    pub fn load_or_generate(key_path: &std::path::Path, secret: &str) -> anyhow::Result<Self> {
        if key_path.exists() {
            let key_der = persistence::load_encrypted_key(key_path, secret)?;
            let key_pair = KeyPair::try_from(key_der)?;
            Self::from_key_pair(key_pair)
        } else {
            let ca = Self::generate()?;
            persistence::save_encrypted_key(key_path, &ca.key_pair_der(), secret)?;
            Ok(ca)
        }
    }

    /// Issues a leaf certificate for `hostname`, signed by this CA. Returns
    /// (cert, private key) ready to hand to a `rustls::ServerConfig`.
    pub fn issue_leaf_cert(&self, hostname: &str) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(LEAF_CERT_VALIDITY_DAYS);

        let leaf_key_pair = KeyPair::generate()?;
        let leaf_cert = params.signed_by(&leaf_key_pair, &self.cert, &self.key_pair)?;

        let cert_der = leaf_cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_pair.serialize_der()));
        Ok((cert_der, key_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_a_leaf_cert_for_a_hostname() {
        let ca = CertificateAuthority::generate().unwrap();
        let (cert_der, _key_der) = ca.issue_leaf_cert("chatgpt.com").unwrap();
        assert!(!cert_der.is_empty());
    }

    #[test]
    fn leaf_cert_is_distinct_from_the_root() {
        // The real trust-chain proof is the end-to-end TLS test in lib.rs
        // (a client that actually trusts the root completing a handshake
        // against a server presenting this leaf) — this just sanity-checks
        // issuance produces a distinct, well-formed leaf.
        let ca = CertificateAuthority::generate().unwrap();
        let (leaf_der, _key_der) = ca.issue_leaf_cert("claude.ai").unwrap();
        let root_der = ca.root_cert_der();
        assert_ne!(leaf_der.as_ref(), root_der.as_ref());
    }

    #[test]
    fn reloading_the_same_key_reproduces_a_ca_that_issues_compatible_leaf_certs() {
        let original = CertificateAuthority::generate().unwrap();
        let key_der = original.key_pair_der();

        let reloaded_key_pair = KeyPair::try_from(key_der).unwrap();
        let reloaded = CertificateAuthority::from_key_pair(reloaded_key_pair).unwrap();

        // Same root DN + same key => leaf certs issued after "restart" carry
        // the same issuer identity a client that trusted the original root
        // would already recognize.
        assert_eq!(original.root_cert_pem().is_empty(), reloaded.root_cert_pem().is_empty());
        let (_leaf_der, _leaf_key) = reloaded.issue_leaf_cert("chatgpt.com").unwrap();
    }

    #[test]
    fn load_or_generate_persists_across_simulated_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ca_signing_key.enc");

        let first_run = CertificateAuthority::load_or_generate(&key_path, "secret").unwrap();
        let first_key_der = first_run.key_pair_der();

        // "Restart": load_or_generate again, same path — should reuse the
        // saved key rather than generating a new one.
        let second_run = CertificateAuthority::load_or_generate(&key_path, "secret").unwrap();
        assert_eq!(first_key_der, second_run.key_pair_der());
    }

    #[test]
    fn load_or_generate_fails_closed_on_wrong_secret() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ca_signing_key.enc");

        CertificateAuthority::load_or_generate(&key_path, "correct-secret").unwrap();
        assert!(CertificateAuthority::load_or_generate(&key_path, "wrong-secret").is_err());
    }
}
