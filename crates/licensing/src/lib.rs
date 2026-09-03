// Ed25519-signed license tokens: the Agent only ever holds a public
// verifying key, so it can check a license but never mint one. Design per
// docs/SafeGateway-Architecture-Review.md §9 — license the endpoint Agent,
// not the gateway or the browser (CrowdStrike/SentinelOne/Zscaler model).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Edition {
    Community,
    Professional,
    /// Added 2026-08-05 per the v1.0 commercial roadmap's seat model (user
    /// decision: "Build UserSeat now") -- 10-250 users, seat-based
    /// licensing, Tenant Portal/Fleet Management/central policy. Sits
    /// between Professional (single-user, device-locked or floating) and
    /// Enterprise (containers/VM appliance/SSO) in the edition ordering
    /// used for display and defaults; `FeatureManager::is_enabled` still
    /// gates actual capabilities off `features`, not this variant, so
    /// adding it here doesn't change what any existing check does.
    Business,
    Enterprise,
}

impl Default for Edition {
    fn default() -> Self {
        Edition::Community
    }
}

/// The signed payload. Field order here is the signing wire format — do not
/// reorder fields without re-issuing every outstanding license, since the
/// signature covers the serialized bytes of this exact struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub tenant: String,
    pub edition: Edition,
    pub max_devices: u32,
    /// One tenant's `max_devices` (Community: 3-5) must all be observed
    /// checking in from the same network — enforced by the Control Plane
    /// reading the source IP a Fleet Management checkin (see
    /// `safeprompt-fleet::DeviceCheckin`, which already embeds the whole
    /// `SignedLicense`) actually arrives from, never by the Agent
    /// self-reporting its own network. An Agent can't be trusted to tell
    /// the truth about a check it would fail, so this field only carries
    /// the *policy* through to wherever it's enforced; it deliberately has
    /// no effect in `LicenseVerifier::verify` below.
    pub site_locked: bool,
    pub expiry: DateTime<Utc>,
    pub features: Vec<String>,
    /// If set, this license is node-locked: it only validates on the device
    /// whose fingerprint matches. `None` for floating/unlocked licenses.
    pub machine_fingerprint: Option<String>,
    /// Cap on how many `ApplicationPolicy` entries the browser extension
    /// may activate at once — "AI Website Protection: 5 sites (Community)
    /// vs. Unlimited (paid)" (user-directed 2026-08-05). `None` means
    /// unlimited, and is also what every license issued before this field
    /// existed deserializes to.
    ///
    /// Both `#[serde(default)]` AND `skip_serializing_if` are required
    /// here, not just the former: `LicenseVerifier::verify` (below) checks
    /// a signature by *re-serializing* `claims` via `canonical_bytes` and
    /// comparing against that freshly-derived byte sequence, not the
    /// original transmitted bytes — a real cross-language canonical-
    /// serialization risk this crate already has to be careful about (see
    /// `canonical_bytes`'s own siblings and the Python `agent_signing.py`
    /// bridge). `#[serde(default)]` alone only affects *deserializing* an
    /// old license missing this field; without `skip_serializing_if`, the
    /// field would still round-trip back out as `"max_ai_sites":null`,
    /// producing different bytes than the license was originally signed
    /// over and breaking every already-issued license's signature the
    /// moment it's next verified. With it, a `None` value is omitted from
    /// re-serialization entirely, so an old license's re-derived bytes are
    /// byte-for-byte identical to what it was actually signed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ai_sites: Option<u32>,
    /// Seat identity: "license people, not devices" (v1.0 commercial
    /// roadmap, user decision 2026-08-05 — "Build UserSeat now... don't
    /// try to retrofit later"). One `seat_id` covers however many devices
    /// `device_limit` allows for *that person* — replacing a laptop just
    /// means the old device ages out of the fleet checkin view, the seat
    /// itself is untouched. `None` for every license issued before this
    /// existed, and for Community's anonymous/no-account model, which has
    /// no seat concept at all (see `email`/`device_limit`'s own comments).
    /// `max_devices` above is unchanged and unrelated: it's still the
    /// tenant-*wide* ceiling across every seat combined, not a per-seat
    /// value -- this field is additive, not a replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat_id: Option<String>,
    /// The seat's identity claim -- "email is the identity, not device"
    /// (same decision as `seat_id`). Populated once a real identity
    /// mechanism exists behind it (Professional: login; Business: Entra
    /// ID/AD/email invitation) -- deliberately not built by this field's
    /// addition alone. `None` for Community's anonymous model and every
    /// pre-existing license.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// This *seat's* device cap (e.g. "up to 5 devices" per person),
    /// distinct from `max_devices`'s tenant-wide total. `None` means
    /// uncapped at the seat level (still subject to `max_devices`
    /// tenant-wide, if that's set meaningfully) -- and is what every
    /// license issued before this field existed deserializes to, same
    /// backward-compatibility story as `max_ai_sites`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_limit: Option<u32>,
    /// When this exact license document was minted -- stamped fresh by
    /// `LicenseIssuer`/`license-tool issue` on every issuance, including
    /// every periodic reissue (`backend/api/agent.py::_sync_license_with_cloud`'s
    /// rolling-window renewal). `None` only for licenses issued before this
    /// field existed; a license missing it is never lease-constrained (see
    /// `max_offline_days`) regardless of what that field says, same
    /// backward-compatibility posture as every other optional field above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    /// Real, offline-verifiable revocation mechanism, closed 2026-08-08 --
    /// without it, revocation does nothing for a device that never checks
    /// in again. If set, this license stops verifying once
    /// `issued_at + max_offline_days` has passed, independent of `expiry`.
    /// A device that keeps checking in gets `issued_at` refreshed on every
    /// reissue (see `_sync_license_with_cloud`), so this is invisible to a
    /// well-behaved device -- but a revoked/suspended/stolen device that
    /// goes dark can no longer hold a valid license indefinitely just
    /// because its nominal subscription `expiry` is still far away; the
    /// worst-case exposure window is bounded by this value instead. `None`
    /// (the default, and what every pre-existing license deserializes to)
    /// means no lease constraint -- deliberately NOT defaulted for every
    /// edition at the crate level (see `license-tool`'s own edition-based
    /// default instead): an edition with no automatic periodic-reissue
    /// channel (Community, Professional -- neither runs Fleet Management
    /// checkins, gated to Business+ by `features::FLEET_MANAGEMENT`) would
    /// have no way to ever refresh this and would silently go dark on its
    /// own schedule regardless of what the customer actually paid for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_offline_days: Option<u32>,
    /// Grace period, closed alongside the above: the number of days *past*
    /// `expiry` this license keeps
    /// verifying successfully, so a delayed renewal/payment or a brief
    /// offline stretch spanning the exact expiry moment doesn't cut off a
    /// paying customer's features at the stroke of midnight with zero
    /// warning. Purely additive/loosening -- unlike `max_offline_days`,
    /// this can never make an otherwise-valid license invalid, so it's
    /// safe to default more broadly (see `license-tool`). `None` (and every
    /// pre-existing license) means no grace window: `expiry` is still a
    /// hard cutoff, exactly today's existing behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    pub claims: LicenseClaims,
    /// Base64-encoded Ed25519 signature over the canonical JSON bytes of `claims`.
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    #[error("license signature is invalid — the token was tampered with or signed by a different key")]
    BadSignature,
    #[error("license expired")]
    Expired,
    #[error("license has not renewed within its allowed offline window — reconnect this device to refresh it")]
    LeaseExpired,
    #[error("license is locked to a different device")]
    FingerprintMismatch,
    #[error("malformed license: {0}")]
    Malformed(String),
}

/// Routes through `serde_json::Value` rather than a direct
/// `serde_json::to_vec(claims)` -- defensive, not fixing a live bug here
/// today: `LicenseClaims` has no `HashMap` fields currently, so a direct
/// `to_vec` is actually fine as things stand. But `safeprompt_policy_sync`'s
/// `canonical_bytes` (identical pattern, identical purpose) had a real,
/// live bug from exactly this shape -- `HashMap`'s randomized per-instance
/// hasher means two structurally-identical documents can serialize their
/// map fields in different key order, so a signer and a verifier working
/// from independently-constructed (e.g. wire-deserialized) instances could
/// disagree on the exact bytes even with unmodified content. Applying the
/// same fix here pre-emptively means a future `HashMap`-typed field added
/// to `LicenseClaims` (e.g. a per-feature limits map) doesn't silently
/// reintroduce that bug -- this workspace never enables serde_json's
/// `preserve_order` feature, so `Value::Object` is a `BTreeMap` and always
/// serializes in sorted key order regardless of the source map's iteration
/// order.
fn canonical_bytes(claims: &LicenseClaims) -> Result<Vec<u8>, LicenseError> {
    let value = serde_json::to_value(claims).map_err(|e| LicenseError::Malformed(e.to_string()))?;
    serde_json::to_vec(&value).map_err(|e| LicenseError::Malformed(e.to_string()))
}

pub struct LicenseIssuer {
    signing_key: SigningKey,
}

impl LicenseIssuer {
    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Generates a fresh random keypair. For dev/test tooling and the
    /// `license-tool keygen` command — never call this in a shipped Agent
    /// binary, which should only ever hold a `LicenseVerifier`'s public key.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand_core::OsRng),
        }
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue(&self, claims: LicenseClaims) -> Result<SignedLicense, LicenseError> {
        let payload = canonical_bytes(&claims)?;
        let signature: Signature = self.signing_key.sign(&payload);
        Ok(SignedLicense {
            claims,
            signature: BASE64.encode(signature.to_bytes()),
        })
    }
}

pub struct LicenseVerifier {
    verifying_key: VerifyingKey,
}

impl LicenseVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, LicenseError> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| LicenseError::Malformed(format!("bad public key: {e}")))?;
        Ok(Self::new(key))
    }

    /// Verifies signature, expiry, and (if the license is node-locked)
    /// that `current_fingerprint` matches. Does not check `max_devices` /
    /// seat counts — that requires a fleet-wide view the endpoint Agent
    /// doesn't have, and belongs in the Control Plane.
    pub fn verify(&self, signed: &SignedLicense, current_fingerprint: &str) -> Result<(), LicenseError> {
        let payload = canonical_bytes(&signed.claims)?;
        let sig_bytes: [u8; 64] = BASE64
            .decode(&signed.signature)
            .map_err(|e| LicenseError::Malformed(format!("bad signature encoding: {e}")))?
            .try_into()
            .map_err(|_| LicenseError::Malformed("signature is not 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| LicenseError::BadSignature)?;

        // Grace-aware expiry: `grace_period_days` (unset = 0, today's exact
        // pre-existing behavior) extends the real cutoff past the nominal
        // `expiry` date rather than replacing it -- the license is still
        // genuinely "expired" for display/renewal-prompt purposes once
        // `expiry` passes (see `grace_status` below), it just keeps
        // *verifying* successfully until the grace window also elapses.
        let grace_days = signed.claims.grace_period_days.unwrap_or(0) as i64;
        let hard_cutoff = signed.claims.expiry + Duration::days(grace_days);
        if hard_cutoff < Utc::now() {
            return Err(LicenseError::Expired);
        }

        // Offline lease: independent of `expiry` entirely. Only enforced
        // when the license actually carries both fields -- see
        // `max_offline_days`'s own doc comment for why this is opt-in
        // rather than always-on.
        if let (Some(issued_at), Some(max_offline_days)) =
            (signed.claims.issued_at, signed.claims.max_offline_days)
        {
            let lease_deadline = issued_at + Duration::days(max_offline_days as i64);
            if lease_deadline < Utc::now() {
                return Err(LicenseError::LeaseExpired);
            }
        }

        if let Some(expected_fingerprint) = &signed.claims.machine_fingerprint {
            if expected_fingerprint != current_fingerprint {
                return Err(LicenseError::FingerprintMismatch);
            }
        }

        Ok(())
    }
}

/// Whether a license is inside, past, or not yet at its grace window --
/// purely a time-based read of `claims`, no cryptographic check involved.
/// Meant to be called *alongside* `LicenseVerifier::verify` on an already
/// signature-verified license (e.g. right after a successful `verify()`
/// call, to decide whether to log/surface a "renew soon" warning), not as a
/// trust decision on its own -- this function has no way to know if `claims`
/// came from a genuinely signed license at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceStatus {
    /// `expiry` hasn't passed yet -- grace isn't relevant.
    NotExpired,
    /// Past `expiry` but still inside the configured grace window --
    /// `verify()` still returns `Ok`, but this license should be renewed.
    InGrace { days_remaining: i64 },
    /// Past both `expiry` and the grace window -- `verify()` now fails with
    /// `LicenseError::Expired`.
    GracePeriodElapsed,
    /// No `grace_period_days` configured on this license at all (`None`,
    /// including every pre-existing license) -- `expiry` is a hard cutoff,
    /// today's exact original behavior.
    NoGraceConfigured,
}

pub fn grace_status(claims: &LicenseClaims) -> GraceStatus {
    let Some(grace_days) = claims.grace_period_days else {
        return GraceStatus::NoGraceConfigured;
    };
    let now = Utc::now();
    if claims.expiry >= now {
        return GraceStatus::NotExpired;
    }
    let hard_cutoff = claims.expiry + Duration::days(grace_days as i64);
    if hard_cutoff < now {
        return GraceStatus::GracePeriodElapsed;
    }
    GraceStatus::InGrace {
        days_remaining: (hard_cutoff - now).num_days(),
    }
}

/// Combines the OS machine ID (Windows registry MachineGuid / Linux
/// machine-id / macOS IOPlatformUUID via the `machine-uid` crate) with the
/// hostname, SHA256-hashed. Deliberately not single-sourced — see
/// docs/SafeGateway-Architecture-Review.md §9 on why one hardware ID alone
/// breaks on routine hardware changes. Known simplification: this uses one
/// OS-level identifier rather than combining CPU ID + motherboard UUID +
/// machine GUID directly; revisit if OS reinstalls prove to change it more
/// than intended.
pub fn compute_machine_fingerprint() -> String {
    let machine_id = machine_uid::get().unwrap_or_else(|_| "unknown-machine".to_string());
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"|");
    hasher.update(hostname.as_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().take(8).map(|b| format!("{b:02X}")).collect::<String>();

    format!("{}-{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
}

/// Canonical feature-flag strings used in `LicenseClaims::features` and
/// checked via `FeatureManager::is_enabled`. Centralized so the issuer side
/// (`license-tool issue --features`) and every gating call site in
/// `apps/service`/`agent/crates/proxy` never drift on spelling. An
/// unlicensed Agent (or a license that omits one of these) runs at
/// `Edition::Community`: core prompt scanning (PII/secrets/**basic**
/// prompt-injection) always works, everything named here does not --
/// including, since 2026-08-10, the advanced/agentic Attack Guardian tiers
/// (see `ATTACK_ADVANCED`/`ATTACK_AGENTIC` below) which used to run
/// unconditionally for every tier, a confirmed real gating gap closed the
/// same day as this comment (see [[safeprompt-attack-gw-reconciliation]]).
pub mod features {
    /// MCP tool-call firewall (`POST /mcp`) — without it, the endpoint
    /// refuses all MCP traffic rather than passing it through unfiltered.
    pub const MCP_FIREWALL: &str = "mcp";
    /// **SIEM syslog export only** (RFC 5424 forwarding to the customer's
    /// own collector), matching the canonical pricing matrix's "SIEM
    /// Integration" row (❌ Community/Professional, Optional Business,
    /// ✅ Enterprise) -- deliberately NOT local audit persistence, which
    /// that same matrix lists as a baseline "✅ every edition" capability
    /// (`apps/service::init_audit_storage` runs unconditionally for exactly
    /// that reason, gated only on whether `SAFEPROMPT_AUDIT_ENCRYPTION_SECRET`
    /// is configured, same as every other always-on baseline scanner --
    /// not behind this or any other feature flag). Found and fixed
    /// 2026-08-08 by a fresh access-control audit across every edition:
    /// this single flag used to gate BOTH local storage and SIEM export
    /// together, which meant Community/Professional -- neither of which is
    /// ever granted "siem" -- got *zero* audit persistence at all, directly
    /// contradicting the matrix's own "Local Audit ✅" row for those
    /// editions. CSV/JSON export (`license-tool audit-export`) reads
    /// straight from the local database file and was never gated on
    /// anything either, so "+ CSV/JSON/SIEM export" in this constant's old
    /// doc comment overstated what it actually controlled.
    pub const AUDIT_SIEM: &str = "siem";
    /// Response-side (model output) DLP scanning, on top of the always-on
    /// request-side scanning.
    pub const RESPONSE_SCANNING: &str = "response_scanning";
    /// CONNECT/TLS-interception forward proxy for browser-based AI coverage.
    pub const BROWSER_COVERAGE: &str = "browser_coverage";
    /// Multi-provider routing/translation (Anthropic/Azure/Gemini/etc) —
    /// without it, requests always go to the single configured upstream.
    pub const MULTI_PROVIDER: &str = "multi_provider";
    /// Signed policy hot-reload from a file/Control Plane source.
    pub const POLICY_SYNC: &str = "policy_sync";
    /// Layer-2 NER scanning (PERSON/ORGANIZATION/LOCATION-class entities a
    /// regex/checksum pattern genuinely can't catch) via the pluggable
    /// `safeprompt_common::Scanner` backend in `safeprompt-scanner` — a
    /// bundled Presidio/spaCy subprocess today, an in-process ONNX model
    /// later. Without it, the always-on Layer-1 regex/checksum scanners
    /// (`safeprompt-pii`/`safeprompt-secrets`/`safeprompt-prompt`) are
    /// unaffected — this only gates the additional Layer-2 pass.
    pub const ADVANCED_NER: &str = "advanced_ner";
    /// Fleet Management checkins (periodic device/posture reporting to the
    /// Control Plane) and the Tenant SPOC role (relaying other devices'
    /// checkins/policy on a LAN) -- both are "centralized management"
    /// capabilities the pricing matrix scopes to Business+ only, not
    /// Community/Professional. Added 2026-08-06: until this, both ran for
    /// any license at all with no feature check (Fleet reporting was gated
    /// on "a valid license exists," not a named feature; the SPOC role had
    /// no gate whatsoever) -- a real discrepancy against the canonical
    /// edition/feature matrix, not a deliberate decision.
    pub const FLEET_MANAGEMENT: &str = "fleet";
    /// Shannon-entropy-based detection of *unknown* secrets (`safeprompt-
    /// secrets::EntropyScanner`) -- Professional+ per the pricing matrix
    /// (2026-08-07), on top of the always-on Layer-1 regex/checksum
    /// secret patterns. Deliberately probabilistic (see that scanner's own
    /// doc comment for the real, accepted false-positive tradeoff), which
    /// is exactly why it's opt-in-by-edition rather than part of
    /// Community's always-on baseline.
    pub const ENTROPY_DETECTION: &str = "entropy";
    /// On-device OCR for image uploads/screenshots and scanned (image-only)
    /// PDF pages (`safeprompt-ocr::OcrEngine`, 2026-08-07).
    ///
    /// **Tier history**: originally Professional+ per the pricing matrix
    /// (2026-08-06), reconciled to Business+ only on 2026-08-08 (real
    /// access-control audit found this doc comment and the matrix
    /// disagreeing; user confirmed Business+, citing real per-file
    /// ONNX-inference CPU/memory cost). **Reopened to Community+
    /// 2026-08-11**: a real live gap surfaced during hands-on testing --
    /// an uploaded passport photo went completely unscanned on a Community
    /// license, since no edition below Business had ever been granted this
    /// feature at all. Explicit user decision to make OCR/image scanning
    /// universal from Community upward rather than starting at Business,
    /// the CPU/memory-cost concern accepted as a real but acceptable
    /// tradeoff for closing that gap. `backend/api/agent.py::
    /// _AGENT_DOWNLOAD_DEFAULTS` now grants `"ocr"` to both `community` and
    /// `professional`; Business/Enterprise licenses already included it via
    /// whoever runs `license-tool issue --features ...` by hand, unchanged
    /// by this reversal. Guarded by `backend/tests/
    /// test_agent_control_plane.py::
    /// test_self_serve_feature_grants_match_the_reconciled_edition_matrix`.
    pub const OCR: &str = "ocr";
    /// AI Attack Guardian, advanced (obfuscation/evasion) tier --
    /// zero-width/RTL unicode obfuscation, fake chat-template role tags,
    /// HTML-comment-hidden instructions, base64 decode-and-rescan
    /// (`safeprompt-attack-advanced::AdvancedAttackScanner::with_advanced`
    /// -- moved out of `safeprompt-prompt` into this private,
    /// `agent-enterprise/`-only crate on 2026-08-27, open-core Phase 3;
    /// `safeprompt-prompt` itself stays public, basic tier only).
    /// Professional+ per SP-ATTACK-002's own ticket tier. The basic tier
    /// (plain-text jailbreak/injection phrasing) is NOT behind this flag --
    /// it's always on, same Community baseline as PII/secrets. Added
    /// 2026-08-10 closing a real gap: before this constant existed, every
    /// capability below ran unconditionally regardless of license (see
    /// [[safeprompt-attack-gw-reconciliation]]).
    pub const ATTACK_ADVANCED: &str = "attack_advanced";
    /// AI Attack Guardian, agentic (tool-abuse/exfiltration/context-flood)
    /// tier -- data exfiltration instructions, tool/shell/file abuse
    /// patterns, context-flood repetition
    /// (`safeprompt-attack-advanced::AdvancedAttackScanner::with_agentic`
    /// -- see `ATTACK_ADVANCED` above for the 2026-08-27 crate move).
    /// Business+ per SP-ATTACK-009/011's own ticket tier -- these are the
    /// two tickets that named a tier explicitly in the tracker; SP-ATTACK-010
    /// (data exfiltration) named none, and was folded into this tier since
    /// exfiltration only matters once an AI app can act on the model's
    /// output, the same "agentic" framing as tool abuse. Added 2026-08-10,
    /// see `ATTACK_ADVANCED` above for the same gating-gap context.
    pub const ATTACK_AGENTIC: &str = "attack_agentic";
    /// Redact-first-verify (2026-08-11, `safeprompt-llm-verify`): an
    /// optional second-opinion LLM classification pass over text that
    /// already passed local (regex/NER/entropy) scanning clean -- real
    /// per-call inference cost, same reasoning as `OCR`/`ADVANCED_NER`
    /// being gated above Professional. Off unless BOTH this feature is
    /// licensed AND a tenant explicitly configures an endpoint -- see
    /// `safeprompt-llm-verify`'s own doc comment for why this crate
    /// refuses to assume a default provider for a customer.
    pub const LLM_VERIFY: &str = "llm_verify";
    /// SP-AUD-004 (2026-08-12): local audit log export
    /// (`local_api::ui_audit_export`, `GET /ui/audit/export`, formats
    /// json/csv/signed) -- Professional+ per SP-AUD-004's own ticket tier.
    /// Local Audit *persistence* itself stays unconditional below this
    /// (see `AUDIT_SIEM`'s doc comment on why storage isn't gated) --
    /// Community still gets its events written and locally queryable via
    /// `license-tool` if it has the file, just not this one-click export
    /// route.
    pub const AUDIT_EXPORT: &str = "audit_export";
}

/// The single place every feature check should go through — never scatter
/// `if licensed` checks through scanner/policy code (see §9). An
/// unlicensed/invalid Agent still runs, just at `Edition::Community`.
pub struct FeatureManager {
    claims: Option<LicenseClaims>,
}

impl FeatureManager {
    pub fn from_verified(claims: LicenseClaims) -> Self {
        Self { claims: Some(claims) }
    }

    pub fn unlicensed() -> Self {
        Self { claims: None }
    }

    pub fn is_enabled(&self, feature: &str) -> bool {
        self.claims
            .as_ref()
            .map(|c| c.features.iter().any(|f| f == feature))
            .unwrap_or(false)
    }

    pub fn edition(&self) -> Edition {
        self.claims.as_ref().map(|c| c.edition).unwrap_or_default()
    }

    pub fn tenant(&self) -> Option<&str> {
        self.claims.as_ref().map(|c| c.tenant.as_str())
    }

    /// Cap on how many AI-site domains the browser extension may cover at
    /// once (see `LicenseClaims::max_ai_sites`'s own doc comment for the
    /// backward-compatibility story). `None` here means "no cap" --
    /// either an unlicensed Agent (which doesn't run browser coverage at
    /// all, so the value is moot) or a license issued with the field
    /// unset, e.g. Enterprise's "customize the site list" tier.
    pub fn max_ai_sites(&self) -> Option<u32> {
        self.claims.as_ref().and_then(|c| c.max_ai_sites)
    }

    /// This license's seat identity, if any -- see `LicenseClaims::seat_id`'s
    /// own doc comment. `None` for an unlicensed Agent, a pre-seat-model
    /// license, or Community's anonymous model.
    pub fn seat_id(&self) -> Option<&str> {
        self.claims.as_ref().and_then(|c| c.seat_id.as_deref())
    }

    pub fn email(&self) -> Option<&str> {
        self.claims.as_ref().and_then(|c| c.email.as_deref())
    }

    pub fn device_limit(&self) -> Option<u32> {
        self.claims.as_ref().and_then(|c| c.device_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(fingerprint: Option<String>, expiry: DateTime<Utc>) -> LicenseClaims {
        LicenseClaims {
            tenant: "Acme Corp".to_string(),
            edition: Edition::Professional,
            max_devices: 25,
            site_locked: false,
            expiry,
            features: vec!["gateway".to_string(), "firewall".to_string(), "pii".to_string()],
            machine_fingerprint: fingerprint,
            max_ai_sites: None,
            seat_id: None,
            email: None,
            device_limit: None,
            issued_at: None,
            max_offline_days: None,
            grace_period_days: None,
        }
    }

    #[test]
    fn issues_and_verifies_a_valid_license() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let claims = sample_claims(None, Utc::now() + Duration::days(365));
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
    }

    #[test]
    fn rejects_a_tampered_license() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let claims = sample_claims(None, Utc::now() + Duration::days(365));
        let mut signed = issuer.issue(claims).unwrap();
        signed.claims.edition = Edition::Enterprise; // tamper after signing

        assert_eq!(verifier.verify(&signed, "any-fingerprint"), Err(LicenseError::BadSignature));
    }

    #[test]
    fn rejects_a_license_signed_by_a_different_key() {
        let issuer = LicenseIssuer::generate();
        let attacker_issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let claims = sample_claims(None, Utc::now() + Duration::days(365));
        let forged = attacker_issuer.issue(claims).unwrap();

        assert_eq!(verifier.verify(&forged, "any-fingerprint"), Err(LicenseError::BadSignature));
    }

    #[test]
    fn a_license_issued_before_max_ai_sites_existed_still_verifies() {
        // Regression test for the exact bug caught while adding this field
        // (2026-08-05): `LicenseVerifier::verify` re-derives the signed
        // bytes via `canonical_bytes(&claims)` and compares against that,
        // not the original transmitted bytes -- so a field that changes
        // serialized output, even by being present-but-null, breaks every
        // already-issued license's signature the moment it's re-verified.
        //
        // Simulates a real pre-existing license.json: a hand-written JSON
        // string with NO "max_ai_sites" key at all (not even null),
        // proving `#[serde(default)]` correctly fills it in as `None` on
        // deserialization.
        let old_style_json = r#"{
            "tenant": "Legacy Corp",
            "edition": "Professional",
            "max_devices": 10,
            "site_locked": false,
            "expiry": "2030-01-01T00:00:00Z",
            "features": ["mcp"],
            "machine_fingerprint": null
        }"#;
        let claims: LicenseClaims = serde_json::from_str(old_style_json).expect("an old license document missing max_ai_sites entirely must still deserialize");
        assert_eq!(claims.max_ai_sites, None);

        // Sign these deserialized claims with the CURRENT issuer -- if
        // `skip_serializing_if` weren't in place, `canonical_bytes` would
        // now emit `"max_ai_sites":null` that was never part of what an
        // old real issuer actually signed, and this round trip wouldn't
        // prove anything about real backward compatibility. Re-serializing
        // immediately and asserting it's byte-identical to the original
        // structure (modulo key order, which serde_json preserves as
        // declaration order for structs either way) is what actually
        // proves the fix.
        let reserialized = serde_json::to_string(&claims).unwrap();
        assert!(!reserialized.contains("max_ai_sites"), "a None max_ai_sites must be omitted from serialization, not emitted as null, or old signatures would break: {reserialized}");

        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());
        let signed = issuer.issue(claims).unwrap();
        assert!(verifier.verify(&signed, "any-fingerprint").is_ok(), "a license carried over from before max_ai_sites existed must still verify correctly");
    }

    #[test]
    fn a_license_with_max_ai_sites_set_round_trips_and_verifies() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.max_ai_sites = Some(5);
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
        assert_eq!(signed.claims.max_ai_sites, Some(5));

        let json = serde_json::to_string(&signed.claims).unwrap();
        assert!(json.contains("\"max_ai_sites\":5"));
        let round_tripped: LicenseClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.max_ai_sites, Some(5));
    }

    #[test]
    fn a_license_issued_before_the_seat_model_existed_still_verifies() {
        // Same regression class as max_ai_sites's own backward-compat test:
        // a hand-written pre-seat-model license.json (no seat_id/email/
        // device_limit keys at all) must still deserialize and verify.
        let old_style_json = r#"{
            "tenant": "Legacy Corp",
            "edition": "Professional",
            "max_devices": 10,
            "site_locked": false,
            "expiry": "2030-01-01T00:00:00Z",
            "features": ["mcp"],
            "machine_fingerprint": null
        }"#;
        let claims: LicenseClaims = serde_json::from_str(old_style_json).expect("a pre-seat-model license must still deserialize");
        assert_eq!(claims.seat_id, None);
        assert_eq!(claims.email, None);
        assert_eq!(claims.device_limit, None);

        let reserialized = serde_json::to_string(&claims).unwrap();
        assert!(!reserialized.contains("seat_id"), "a None seat_id must be omitted from serialization: {reserialized}");
        assert!(!reserialized.contains("\"email\""), "a None email must be omitted from serialization: {reserialized}");
        assert!(!reserialized.contains("device_limit"), "a None device_limit must be omitted from serialization: {reserialized}");

        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());
        let signed = issuer.issue(claims).unwrap();
        assert!(verifier.verify(&signed, "any-fingerprint").is_ok(), "a pre-seat-model license must still verify correctly");
    }

    #[test]
    fn a_license_with_a_seat_assigned_round_trips_and_verifies() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.edition = Edition::Business;
        claims.seat_id = Some("USR-001".to_string());
        claims.email = Some("john@company.com".to_string());
        claims.device_limit = Some(5);
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
        assert_eq!(signed.claims.seat_id.as_deref(), Some("USR-001"));

        let json = serde_json::to_string(&signed.claims).unwrap();
        let round_tripped: LicenseClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.seat_id.as_deref(), Some("USR-001"));
        assert_eq!(round_tripped.email.as_deref(), Some("john@company.com"));
        assert_eq!(round_tripped.device_limit, Some(5));
        assert_eq!(round_tripped.edition, Edition::Business);
    }

    #[test]
    fn feature_manager_exposes_seat_identity() {
        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.seat_id = Some("USR-001".to_string());
        claims.email = Some("john@company.com".to_string());
        claims.device_limit = Some(5);
        let manager = FeatureManager::from_verified(claims);

        assert_eq!(manager.seat_id(), Some("USR-001"));
        assert_eq!(manager.email(), Some("john@company.com"));
        assert_eq!(manager.device_limit(), Some(5));
    }

    #[test]
    fn feature_manager_has_no_seat_identity_when_the_license_predates_the_seat_model() {
        let manager = FeatureManager::from_verified(sample_claims(None, Utc::now() + Duration::days(365)));
        assert_eq!(manager.seat_id(), None);
        assert_eq!(manager.email(), None);
        assert_eq!(manager.device_limit(), None);
    }

    #[test]
    fn rejects_an_expired_license() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let claims = sample_claims(None, Utc::now() - Duration::days(1));
        let signed = issuer.issue(claims).unwrap();

        assert_eq!(verifier.verify(&signed, "any-fingerprint"), Err(LicenseError::Expired));
    }

    #[test]
    fn rejects_a_node_locked_license_on_the_wrong_device() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let claims = sample_claims(Some("AAAA-BBBB-CCCC-DDDD".to_string()), Utc::now() + Duration::days(365));
        let signed = issuer.issue(claims).unwrap();

        assert_eq!(
            verifier.verify(&signed, "1111-2222-3333-4444"),
            Err(LicenseError::FingerprintMismatch)
        );
        assert!(verifier.verify(&signed, "AAAA-BBBB-CCCC-DDDD").is_ok());
    }

    #[test]
    fn feature_manager_gates_on_token_features() {
        let manager = FeatureManager::from_verified(sample_claims(None, Utc::now() + Duration::days(1)));
        assert!(manager.is_enabled("gateway"));
        assert!(!manager.is_enabled("mcp"));
        assert_eq!(manager.edition(), Edition::Professional);
    }

    #[test]
    fn unlicensed_agent_defaults_to_community_with_no_features() {
        let manager = FeatureManager::unlicensed();
        assert!(!manager.is_enabled("gateway"));
        assert_eq!(manager.edition(), Edition::Community);
    }

    #[test]
    fn machine_fingerprint_is_stable_across_calls() {
        assert_eq!(compute_machine_fingerprint(), compute_machine_fingerprint());
    }

    #[test]
    fn a_license_with_no_lease_or_grace_fields_behaves_exactly_as_before() {
        // Backward-compat regression, same class as the max_ai_sites/seat
        // model tests above: a hand-written pre-existing license.json with
        // none of the three new fields must still deserialize and verify
        // with EXACTLY today's original semantics -- hard expiry cutoff, no
        // lease constraint at all.
        let old_style_json = r#"{
            "tenant": "Legacy Corp",
            "edition": "Professional",
            "max_devices": 10,
            "site_locked": false,
            "expiry": "2030-01-01T00:00:00Z",
            "features": ["mcp"],
            "machine_fingerprint": null
        }"#;
        let claims: LicenseClaims = serde_json::from_str(old_style_json).expect("a license predating lease/grace fields must still deserialize");
        assert_eq!(claims.issued_at, None);
        assert_eq!(claims.max_offline_days, None);
        assert_eq!(claims.grace_period_days, None);

        let reserialized = serde_json::to_string(&claims).unwrap();
        assert!(!reserialized.contains("issued_at"), "a None issued_at must be omitted from serialization: {reserialized}");
        assert!(!reserialized.contains("max_offline_days"), "a None max_offline_days must be omitted from serialization: {reserialized}");
        assert!(!reserialized.contains("grace_period_days"), "a None grace_period_days must be omitted from serialization: {reserialized}");

        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());
        let signed = issuer.issue(claims).unwrap();
        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
        assert_eq!(grace_status(&signed.claims), GraceStatus::NoGraceConfigured);
    }

    #[test]
    fn a_license_past_expiry_with_no_grace_configured_still_fails_hard() {
        // Exactly today's pre-existing behavior when grace_period_days is
        // unset: expiry is still a hard cutoff, zero tolerance.
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() - Duration::hours(1));
        claims.grace_period_days = None;
        let signed = issuer.issue(claims).unwrap();

        assert_eq!(verifier.verify(&signed, "any-fingerprint"), Err(LicenseError::Expired));
        assert_eq!(grace_status(&signed.claims), GraceStatus::NoGraceConfigured);
    }

    #[test]
    fn a_license_past_expiry_but_inside_its_grace_window_still_verifies() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() - Duration::days(2));
        claims.grace_period_days = Some(7);
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok(), "2 days past expiry with a 7-day grace window must still verify");
        match grace_status(&signed.claims) {
            GraceStatus::InGrace { days_remaining } => assert!((1..=5).contains(&days_remaining), "expected roughly 5 days of grace left, got {days_remaining}"),
            other => panic!("expected InGrace, got {other:?}"),
        }
    }

    #[test]
    fn a_license_past_both_expiry_and_its_grace_window_fails() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() - Duration::days(10));
        claims.grace_period_days = Some(7);
        let signed = issuer.issue(claims).unwrap();

        assert_eq!(verifier.verify(&signed, "any-fingerprint"), Err(LicenseError::Expired), "10 days past expiry with only a 7-day grace window must fail");
        assert_eq!(grace_status(&signed.claims), GraceStatus::GracePeriodElapsed);
    }

    #[test]
    fn a_stale_license_past_its_offline_lease_fails_even_with_expiry_far_away() {
        // The actual revocation mechanism: a device that stops checking in
        // can no longer hold a valid license indefinitely just because its
        // nominal subscription expiry is still a year away.
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.issued_at = Some(Utc::now() - Duration::days(10));
        claims.max_offline_days = Some(7);
        let signed = issuer.issue(claims).unwrap();

        assert_eq!(verifier.verify(&signed, "any-fingerprint"), Err(LicenseError::LeaseExpired));
    }

    #[test]
    fn a_recently_issued_license_within_its_offline_lease_still_verifies() {
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.issued_at = Some(Utc::now() - Duration::days(2));
        claims.max_offline_days = Some(7);
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
    }

    #[test]
    fn a_license_with_issued_at_but_no_max_offline_days_is_never_lease_constrained() {
        // Both fields are required together (see `max_offline_days`'s own
        // doc comment) -- issued_at alone, with no configured lease length,
        // must never fail on its own no matter how old it is.
        let issuer = LicenseIssuer::generate();
        let verifier = LicenseVerifier::new(issuer.verifying_key());

        let mut claims = sample_claims(None, Utc::now() + Duration::days(365));
        claims.issued_at = Some(Utc::now() - Duration::days(3650));
        claims.max_offline_days = None;
        let signed = issuer.issue(claims).unwrap();

        assert!(verifier.verify(&signed, "any-fingerprint").is_ok());
    }
}
