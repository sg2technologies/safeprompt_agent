// Policy-driven agent redesign (decided 2026-08-03): rather than a handful
// of flat booleans, the policy is now three layers -- matching the
// SafePrompt Agent architecture review's "Capability / Application /
// Security" split:
//
//   1. `CapabilityPolicy`  -- which connector types may run at all
//      (browser / desktop AI / API proxy / office upload).
//   2. `applications`      -- a policy-driven registry of governed AI
//      applications, matched by domain. This is what makes "any URL, not
//      just chatgpt.com/claude.ai" possible: nothing in this crate (or the
//      proxy that consults it) hardcodes a fixed set of AI sites anymore --
//      admins add/remove entries here, in the signed policy document, with
//      no code change.
//   3. `SecurityPolicy`    -- which detector categories are active, and
//      what to do when they fire.
//
// Plus `uploads`: a per-file-extension action (allow/inspect/block),
// consulted by the proxy's multipart handling (see
// safeprompt-file-inspector's integration in agent/crates/proxy) before it
// even bothers extracting/scanning a file's content.

use safeprompt_common::{Action, Finding, FindingCategory};
use safeprompt_risk::{RiskContext, RiskEngine, RiskScore};
use safeprompt_rules::{Condition, Rule, RuleEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_true() -> bool {
    true
}

// ── Capability policy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    #[serde(default = "default_true")]
    pub browser: bool,
    /// Desktop AI apps (ChatGPT Desktop, Claude Desktop, Cursor, ...) --
    /// reserved for a future connector; defaults off since nothing consumes
    /// it yet, unlike `browser`/`api_proxy` which the CONNECT proxy and
    /// local reverse-proxy already implement.
    #[serde(default)]
    pub desktop_ai: bool,
    #[serde(default = "default_true")]
    pub api_proxy: bool,
    #[serde(default = "default_true")]
    pub office_upload: bool,
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self { browser: true, desktop_ai: false, api_proxy: true, office_upload: true }
    }
}

// ── Application registry ────────────────────────────────────────────────────

/// One governed application, matched by domain -- NOT a hardcoded name.
/// "chatgpt"/"claude"/"cursor" are just conventional `id` values a policy
/// author chooses; the matching logic only ever looks at `match_domains`.
/// Adding support for a new AI site tomorrow is a policy-document change,
/// not a code change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationPolicy {
    pub id: String,
    #[serde(default)]
    pub match_domains: Vec<String>,
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub upload: bool,
    #[serde(default = "default_true")]
    pub prompt_scan: bool,
    #[serde(default = "default_true")]
    pub response_scan: bool,
    /// Opt this domain into the CONNECT proxy's TLS-interception MITM path
    /// (`agent/crates/connect_proxy`), on top of whatever coverage the
    /// browser extension already gives it. Deliberately a SEPARATE opt-in
    /// from `enabled` -- most `applications` entries exist purely to govern
    /// browser-extension behavior (upload/prompt_scan/response_scan for a
    /// site the extension already covers structurally), and every major
    /// hosted AI chat vendor's upstream fingerprints and blocks this proxy's
    /// own outbound TLS handshake (see `connect_proxy::sni_gate`'s own doc
    /// comment -- chatgpt.com/openai.com/gemini.google.com/claude.ai/
    /// anthropic.com/perplexity.ai/grok.com/x.ai all confirmed broken this
    /// way). If this field defaulted to following `enabled`, a completely
    /// ordinary tenant policy entry for "chatgpt" (added just so an admin
    /// can toggle its upload/prompt_scan settings) would silently start
    /// attempting CONNECT-proxy MITM on chatgpt.com again -- exactly the bug
    /// that policy was built to leave behind. `#[serde(default)]` = `false`,
    /// so every existing/typical policy document leaves this off and only
    /// an admin explicitly opting a *specific, non-major-vendor* domain
    /// (an internal/self-hosted AI tool, typically) turns it on.
    #[serde(default)]
    pub connect_proxy: bool,
}

// ── Upload policy ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadAction {
    Allow,
    Inspect,
    Block,
}

// ── Security policy ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Action for a finding category with no explicit entry in `actions`.
    pub default_action: Action,
    /// Which detector categories are active at all. Layer-1 scanners
    /// (regex/checksum) still run unconditionally -- they're cheap -- but a
    /// disabled category's findings are filtered out before
    /// `PolicyEngine::evaluate` ever sees them, same observable effect as
    /// not scanning for it.
    #[serde(default = "default_detectors")]
    pub detectors: HashMap<FindingCategory, bool>,
    /// What to do when a finding IS produced, per category.
    #[serde(default = "default_actions")]
    pub actions: HashMap<FindingCategory, Action>,
    /// What to do with a file/image upload whose detector verdict is
    /// Redact ("Mask it") when this file's format can't be safely masked
    /// in place. Masking a chat *message* just substitutes text in a JSON
    /// string; masking inside a *file* means safely splicing redacted
    /// content back into that file's own byte format -- straightforward
    /// for plain text (.txt/.csv/.md/.json, see
    /// `safeprompt_local_api::is_text_redactable_extension`), genuinely
    /// hard for anything with real internal structure (.docx/.pdf) or
    /// that isn't text at all (images). For those, this setting is what
    /// actually happens instead of masking.
    ///
    /// Defaults to `Block` -- the only behavior that existed before this
    /// field was added (previously hardcoded, invisible to an admin
    /// reading the policy). Now an explicit, documented choice: a tenant
    /// that would rather let an unmaskable secret-bearing file through
    /// with just a flag can set this to `Warn`/`Audit` instead.
    #[serde(default = "default_unmaskable_file_action")]
    pub unmaskable_file_action: Action,
    /// 2026-09-04: a real, live user request for a genuinely simple "just
    /// let me send this one file, I know what's in it" lever -- the
    /// existing per-category checkbox+dropdown model (turn off/reconfigure
    /// PII, then remember to turn it back on) was confirmed live to be
    /// too many steps and too easy to leave in the wrong state for
    /// someone who isn't already fluent in this policy's own vocabulary.
    ///
    /// A Unix timestamp (seconds), not a bool -- modeled on how consumer
    /// antivirus products offer "pause protection for 15 min / 1 hour,"
    /// not an indefinite off-switch, specifically so forgetting to turn
    /// it back on doesn't leave a device permanently unprotected. `None`
    /// or a value at/before now means not paused. Deliberately bypasses
    /// detection/redaction only (`Inspector::inspect`/`inspect_response`)
    /// -- NOT `upload_action`'s per-extension allow/block list, which is
    /// a structural "never allow .exe uploads" type decision this pause
    /// has no business touching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_secs: Option<i64>,
}

fn default_unmaskable_file_action() -> Action {
    Action::Block
}

impl SecurityPolicy {
    /// True while a pause set via `paused_until_unix_secs` is still in its
    /// window. Reads real wall-clock time (`SystemTime::now`), not a
    /// caller-supplied "now" -- this is a real, external pause a human set
    /// from the console, not something a test needs to freeze/control
    /// (existing tests that care about determinism don't set this field at
    /// all, so it stays `None` -- not paused -- for every one of them).
    pub fn is_paused(&self) -> bool {
        let Some(until) = self.paused_until_unix_secs else { return false };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now < until
    }
}

fn default_detectors() -> HashMap<FindingCategory, bool> {
    use FindingCategory::*;
    [Pii, Secret, PromptInjection, CustomKeyword, Financial, Internal, Toxicity]
        .into_iter()
        .map(|c| (c, true))
        .collect()
}

/// Changed 2026-08-05 (user-directed): Secret now defaults to Redact, not
/// Block. The old default matched the pre-redesign flat-boolean engine
/// (`block_on_secrets` true), but blocking on every API key/credential
/// meant a single leaked-looking token anywhere in a request (including
/// false positives) killed the whole message outright. Masking is the
/// better default for the same reason it already was for PII/financial/
/// internal-hostname/custom-keyword: the sensitive value never reaches the
/// LLM either way, but the rest of a legitimate message still goes
/// through. PromptInjection stays Block -- there's no sensible way to
/// "redact" an injection attempt, the whole point is refusing it.
fn default_actions() -> HashMap<FindingCategory, Action> {
    use FindingCategory::*;
    HashMap::from([
        (Secret, Action::Redact),
        (PromptInjection, Action::Block),
        (Pii, Action::Redact),
        (Financial, Action::Redact),
        (Internal, Action::Redact),
        (CustomKeyword, Action::Redact),
        // Warn, not Block: Toxicity spans CRITICAL (threats/self-harm) down
        // to LOW (profanity) severity under one category (see
        // `safeprompt-guardrails`'s own doc comment on why match_name-level
        // actions aren't wired up yet), and this lookup only ever sees the
        // category, never the severity. Warn is the safer category-wide
        // default -- it surfaces every hit for audit rather than either
        // silently allowing it (Allow) or hard-blocking routine profanity
        // (Block). A tenant wanting stricter enforcement on the severe end
        // can add a Rule Engine rule on `RiskScoreAtLeast` instead, since
        // the Risk Engine (unlike this lookup) does weight by severity.
        (Toxicity, Action::Warn),
    ])
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            detectors: default_detectors(),
            actions: default_actions(),
            unmaskable_file_action: default_unmaskable_file_action(),
            paused_until_unix_secs: None,
        }
    }
}

/// Worst-to-best ranking across all six `Action` variants (extended
/// 2026-08-10, SP-RISK-003, from the original four). `Audit` ranks just
/// above `Allow` -- it's non-disruptive, the same as Allow from the
/// requester's point of view, just flagged for elevated audit visibility
/// (see `Action::Audit`'s own doc comment). `RequireApproval` ranks below
/// `Block` but above `Redact` -- pausing a request for a human decision is
/// more disruptive than masking (nothing proceeds automatically) but isn't
/// a hard, permanent denial the way `Block` is.
fn action_rank(action: &Action) -> u8 {
    match action {
        Action::Allow => 0,
        Action::Audit => 1,
        Action::Warn => 2,
        Action::Redact => 3,
        Action::RequireApproval => 4,
        Action::Block => 5,
    }
}

// ── Custom keyword rules ────────────────────────────────────────────────────

/// One tenant-configured word/phrase — a company name, a project codename,
/// a competitor's name, anything the built-in PII/Secret/Financial/Internal
/// detectors don't already cover. Decided 2026-08-05 (user-directed): each
/// rule carries its OWN action rather than sharing one action for the whole
/// `CustomKeyword` category, since the actual use case is genuinely mixed —
/// "OurCompanyName" should mask, a public product name should pass through
/// untouched, a competitor's name might warrant an outright block. Matching
/// on `finding.match_name` (set to `pattern` by the scanner) rather than
/// adding a new field to `Finding` keeps this entirely local to the
/// policy/scanning layer -- no ripple through the ~10 other call sites that
/// construct a `Finding` today.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomKeywordRule {
    pub pattern: String,
    pub action: Action,
    #[serde(default)]
    pub case_sensitive: bool,
}

// ── Top-level policy document ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub capabilities: CapabilityPolicy,
    #[serde(default)]
    pub applications: Vec<ApplicationPolicy>,
    #[serde(default)]
    pub uploads: HashMap<String, UploadAction>,
    #[serde(default)]
    pub security: SecurityPolicy,
    /// Default empty -- by default, no custom keywords are configured (the
    /// built-in detectors run regardless). Mask-by-default per-rule only
    /// applies once a tenant admin actually adds one; see `default_action`
    /// on `add_keyword`-style policy-authoring tooling (Control Plane side,
    /// not this crate) for the "defaults to mask" UX decision.
    #[serde(default)]
    pub custom_keywords: Vec<CustomKeywordRule>,
    /// SP-RISK-002/SP-RISK-003 conditional rules (`safeprompt_rules::Rule`)
    /// — travels with the rest of the policy document the same way
    /// `custom_keywords` already does, closing the gap SP-RISK-002's own
    /// notes flagged ("no policy-document schema for authoring rules
    /// centrally yet"). Default empty, same "admin populates it" convention
    /// as every other field here.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            capabilities: CapabilityPolicy::default(),
            applications: Vec::new(),
            uploads: HashMap::new(),
            security: SecurityPolicy::default(),
            custom_keywords: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl PolicyConfig {
    /// Finds the application entry matching `domain` -- exact match or
    /// subdomain of a listed `match_domains` entry (so `chat.openai.com`
    /// matches an entry listing `openai.com`). Returns `None` for a domain
    /// with no matching entry; callers decide what "no entry" means (this
    /// crate never hardcodes "unknown = blocked" or "unknown = allowed").
    pub fn resolve_application(&self, domain: &str) -> Option<&ApplicationPolicy> {
        let domain = domain.to_ascii_lowercase();
        self.applications.iter().find(|app| {
            app.match_domains.iter().any(|d| {
                let d = d.to_ascii_lowercase();
                domain == d || domain.ends_with(&format!(".{d}"))
            })
        })
    }

    /// What to do with a file upload of this extension (case-insensitive,
    /// leading dot optional). No matching entry defaults to `Inspect` --
    /// scan it, the safe default, same as if `uploads` were never
    /// configured at all.
    pub fn upload_action(&self, extension: &str) -> UploadAction {
        let ext = extension.trim_start_matches('.').to_ascii_lowercase();
        self.uploads.get(&ext).copied().unwrap_or(UploadAction::Inspect)
    }
}

/// SP-RISK-003's full pipeline output — `evaluate` (the pre-existing,
/// findings-only entry point) collapses this down to just `action` for
/// every caller that predates this ticket. `risk`/`matched_rules` are
/// exposed for a caller that wants to show *why* (audit trail, a future
/// local-console UI panel) -- same transparency goal `RiskScore.signals`
/// and `RuleEngine::matched_rules` already serve one layer down.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecision {
    pub action: Action,
    pub risk: RiskScore,
    /// Names of every rule that matched, in configured order — not just the
    /// one whose action happened to be worst.
    pub matched_rules: Vec<String>,
}

pub struct PolicyEngine {
    config: PolicyConfig,
    /// SP-RISK-001 — default weights today (not yet tenant-configurable via
    /// `PolicyConfig`; see `evaluate_with_context`'s own doc comment for why
    /// that's a deliberately deferred, documented gap rather than an
    /// oversight).
    risk_engine: RiskEngine,
    /// SP-RISK-002 — rebuilt from `config.rules` on every `new`/construction,
    /// same "policy swap replaces the whole engine" pattern `update_policy`
    /// (in `safeprompt-inspector`) already uses for this entire struct.
    rule_engine: RuleEngine,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        let rule_engine = RuleEngine::new(config.rules.clone());
        Self { config, risk_engine: RiskEngine::default(), rule_engine }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// The pre-SP-RISK-003 entry point, unchanged in signature and — for
    /// every existing caller — unchanged in output: equivalent to
    /// `evaluate_with_context(findings, &RiskContext::default()).action`.
    /// Identical because an unconfigured `PolicyConfig` (`rules: vec![]`,
    /// the default for every existing test and call site) makes
    /// `RuleEngine::evaluate` return `None` for any context, so the
    /// category-lookup result below is never overridden. Kept as the
    /// primary API for callers that only want an `Action` and have no
    /// `RiskContext` to supply (most of `safeprompt-inspector` today — see
    /// its own module for why threading full request context there is
    /// still open work).
    pub fn evaluate(&self, findings: &[Finding]) -> Action {
        self.evaluate_with_context(findings, &RiskContext::default()).action
    }

    /// SP-RISK-003's real pipeline: **Detection** (`findings`, already
    /// collected by the caller) **→ Risk** (`safeprompt_risk::RiskEngine`)
    /// **→ Rules** (`safeprompt_rules::RuleEngine`, consulted WITH the just-
    /// computed risk score, so a rule can key off `RiskScoreAtLeast`/
    /// `RiskBandAtLeast`) **→ Policy** (the pre-existing per-category
    /// `actions` lookup below) **→ Action** (worst-of the policy lookup and
    /// every matched rule's action — same "worst wins" convention used
    /// throughout this codebase, at every layer: across findings within the
    /// category lookup, across matched rules within `RuleEngine::evaluate`,
    /// and now across those two results here).
    ///
    /// Known, accepted scope limit: `risk_engine` always uses default
    /// weights — `PolicyConfig` has no field to override them yet. Unlike
    /// `rules`/`custom_keywords`, this wasn't literally required by
    /// SP-RISK-003's own text ("Actions: Allow/Warn/Mask/Block/Audit/Require
    /// Approval", not "configurable weights"), and a rule author can already
    /// express anything weight-tuning would achieve via `RiskScoreAtLeast`/
    /// `RiskBandAtLeast` thresholds on top of the fixed default scoring —
    /// left as a documented future enhancement rather than expanding this
    /// ticket's scope further.
    pub fn evaluate_with_context(&self, findings: &[Finding], context: &RiskContext) -> PolicyDecision {
        let category_action = self.category_action(findings);

        let risk = self.risk_engine.score(findings, context);
        let matched = self.rule_engine.matched_rules(findings, context, Some(&risk));
        let rule_action = matched.iter().map(|rule| rule.action).max_by_key(action_rank);

        let action = match rule_action {
            Some(rule_action) if action_rank(&rule_action) > action_rank(&category_action) => rule_action,
            _ => category_action,
        };

        PolicyDecision { action, risk, matched_rules: matched.into_iter().map(|rule| rule.name.clone()).collect() }
    }

    /// Worst-of across every *active* (detector-enabled) finding: Block >
    /// RequireApproval > Redact > Warn > Audit > Allow (see `action_rank`).
    /// A `CustomKeyword` finding is resolved against `custom_keywords` first
    /// (by `match_name`, which the scanner sets to the literal rule pattern
    /// that matched) -- that's what gives each configured word its own
    /// action instead of sharing one category-wide setting. Any other
    /// category, or a `CustomKeyword` finding whose rule somehow isn't
    /// found (shouldn't normally happen), falls back to the existing
    /// category → `actions` → `default_action` lookup. Renamed from the
    /// pre-SP-RISK-003 `evaluate` (whose name and signature `evaluate` above
    /// now preserves as a thin wrapper) -- this is purely the "Policy" step
    /// of the Detection→Risk→Rules→Policy→Action pipeline.
    fn category_action(&self, findings: &[Finding]) -> Action {
        let sec = &self.config.security;
        let mut worst = Action::Allow;

        for finding in findings {
            if !*sec.detectors.get(&finding.category).unwrap_or(&true) {
                continue;
            }
            let action = if finding.category == FindingCategory::CustomKeyword {
                self.config
                    .custom_keywords
                    .iter()
                    .find(|r| r.pattern == finding.match_name)
                    .map(|r| r.action)
                    .unwrap_or_else(|| sec.actions.get(&finding.category).copied().unwrap_or(sec.default_action))
            } else {
                sec.actions.get(&finding.category).copied().unwrap_or(sec.default_action)
            };
            if action_rank(&action) > action_rank(&worst) {
                worst = action;
            }
        }

        worst
    }
}

// ── Compliance packs ────────────────────────────────────────────────────────

/// Versioned, named `PolicyConfig` presets tuned for a specific compliance
/// regime. A full Policy Language DSL turns out not to be a prerequisite
/// for this at all — a pack is just a Rust factory function producing an
/// ordinary `PolicyConfig`,
/// the same type every other policy already is. User picked PCI-DSS as the
/// first pack to build (2026-08-12), narrowest and most concrete since
/// checksum-validated card-number detection (`FindingCategory::Financial`)
/// already exists — the pack is mostly a matter of choosing the right
/// default action and rule around a detector that was already there, not
/// building new detection.
///
/// Each pack is named with an explicit version suffix (`_v1`) so a
/// tenant's chosen pack stays auditable/reproducible even after a later
/// release changes what "the PCI-DSS pack" defaults to — selecting
/// `PCI_DSS_V1` should always mean the same ruleset it meant today, not
/// silently drift.
pub mod packs {
    use super::{Action, Condition, FindingCategory, PolicyConfig, Rule};

    pub const PCI_DSS_V1: &str = "pci_dss_v1";

    /// PCI-DSS Requirement 3 (protect stored cardholder data) / Requirement
    /// 4 (encrypt transmission of cardholder data across open networks):
    /// starts from `PolicyConfig::default()` (so every other detector keeps
    /// its ordinary default) and tightens exactly the `Financial` category
    /// two ways:
    ///   1. The bare category action moves from the platform default
    ///      (`Redact`) to `Block` — masking satisfies "not stored/
    ///      transmitted in the clear," but this pack treats sending even a
    ///      masked card number to a destination outside the cardholder
    ///      data environment as out-of-scope exfiltration, not an
    ///      acceptable outcome.
    ///   2. An explicit named rule duplicates that as a Rule Engine entry
    ///      (`Condition::CategoryDetected(Financial) -> Block`) — belt and
    ///      suspenders with #1, but named/auditable on its own in
    ///      `PolicyDecision::matched_rules` so a compliance reviewer can
    ///      see "the PCI-DSS pack's rule fired" in the audit trail, not
    ///      just an unattributed category-default block.
    ///
    /// **Known simplification, stated plainly**: `Financial` today also
    /// covers IBAN/ABA routing numbers, not just payment-card numbers —
    /// there's no separate card-only category yet, so this pack is
    /// currently broader than PCI-DSS strictly requires (protects all
    /// financial-account-number-shaped data, not just cardholder data). A
    /// real gap if a tenant specifically wants IBAN/routing numbers to
    /// stay at the ordinary Redact default while card numbers alone get
    /// Block — not built here, flagged rather than silently assumed out of
    /// scope.
    pub fn pci_dss_v1() -> PolicyConfig {
        let mut config = PolicyConfig::default();
        config.security.actions.insert(FindingCategory::Financial, Action::Block);
        config.rules.push(Rule {
            name: format!("{PCI_DSS_V1}: block cardholder/financial data to any destination"),
            condition: Condition::CategoryDetected(FindingCategory::Financial),
            action: Action::Block,
        });
        config
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::PolicyEngine;
        use safeprompt_common::Finding;

        fn card_finding() -> Finding {
            Finding {
                category: FindingCategory::Financial,
                match_name: "CREDIT_CARD".to_string(),
                snippet: "4111111111111111".to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_CARD]".to_string()),
            }
        }

        #[test]
        fn blocks_cardholder_data_instead_of_the_platform_default_redact() {
            let default_engine = PolicyEngine::new(PolicyConfig::default());
            assert_eq!(default_engine.evaluate(&[card_finding()]), Action::Redact, "sanity check: the platform default really is Redact, not already Block");

            let pci_engine = PolicyEngine::new(pci_dss_v1());
            assert_eq!(pci_engine.evaluate(&[card_finding()]), Action::Block);
        }

        #[test]
        fn the_named_rule_appears_in_matched_rules_for_audit() {
            let engine = PolicyEngine::new(pci_dss_v1());
            let decision = engine.evaluate_with_context(&[card_finding()], &safeprompt_risk::RiskContext::default());
            assert!(decision.matched_rules.iter().any(|name| name.starts_with(PCI_DSS_V1)));
        }

        #[test]
        fn every_other_category_keeps_the_ordinary_platform_default() {
            let engine = PolicyEngine::new(pci_dss_v1());
            let pii = Finding { category: FindingCategory::Pii, match_name: "EMAIL".to_string(), snippet: "a@b.com".to_string(), severity: "LOW".to_string(), redacted_replacement: None };
            assert_eq!(engine.evaluate(&[pii]), Action::Redact, "PCI-DSS pack must only tighten Financial, not silently change every category's default");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: FindingCategory) -> Finding {
        Finding {
            category,
            match_name: "test".to_string(),
            snippet: "snippet".to_string(),
            severity: "MEDIUM".to_string(),
            redacted_replacement: None,
        }
    }

    #[test]
    fn default_policy_redacts_secrets() {
        // Changed 2026-08-05: Secret now masks by default like PII/financial/
        // internal/custom-keyword, rather than blocking the whole message.
        let engine = PolicyEngine::default();
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Secret)]), Action::Redact);
    }

    #[test]
    fn default_policy_blocks_prompt_injection() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.evaluate(&[finding(FindingCategory::PromptInjection)]), Action::Block);
    }

    #[test]
    fn default_policy_redacts_pii() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Pii)]), Action::Redact);
    }

    #[test]
    fn no_findings_allows() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.evaluate(&[]), Action::Allow);
    }

    fn now_unix_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    #[test]
    fn security_policy_defaults_to_not_paused() {
        assert!(!SecurityPolicy::default().is_paused());
    }

    #[test]
    fn security_policy_is_paused_while_the_timestamp_is_in_the_future() {
        let mut policy = SecurityPolicy::default();
        policy.paused_until_unix_secs = Some(now_unix_secs() + 900);
        assert!(policy.is_paused());
    }

    #[test]
    fn security_policy_is_not_paused_once_the_timestamp_is_in_the_past() {
        let mut policy = SecurityPolicy::default();
        policy.paused_until_unix_secs = Some(now_unix_secs() - 1);
        assert!(!policy.is_paused());
    }

    #[test]
    fn worst_of_multiple_findings_wins() {
        let engine = PolicyEngine::default();
        // PII/Secret alone both redact now, but prompt injection in the same
        // batch must still block -- there's no sensible way to redact an
        // injection attempt.
        let action = engine.evaluate(&[finding(FindingCategory::Pii), finding(FindingCategory::PromptInjection)]);
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn disabled_detector_is_ignored_even_if_it_would_otherwise_block() {
        let mut config = PolicyConfig::default();
        config.security.detectors.insert(FindingCategory::Secret, false);
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Secret)]), Action::Allow);
    }

    #[test]
    fn custom_action_override_takes_effect() {
        let mut config = PolicyConfig::default();
        config.security.actions.insert(FindingCategory::Pii, Action::Warn);
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Pii)]), Action::Warn);
    }

    #[test]
    fn resolves_application_by_exact_and_subdomain_match() {
        let config = PolicyConfig {
            applications: vec![ApplicationPolicy {
                id: "chatgpt".to_string(),
                match_domains: vec!["openai.com".to_string()],
                enabled: true,
                upload: true,
                prompt_scan: true,
                response_scan: true,
                connect_proxy: false,
            }],
            ..PolicyConfig::default()
        };

        assert!(config.resolve_application("openai.com").is_some());
        assert!(config.resolve_application("api.openai.com").is_some());
        assert!(config.resolve_application("chat.openai.com").is_some());
        assert!(config.resolve_application("notopenai.com").is_none());
        assert!(config.resolve_application("anthropic.com").is_none());
    }

    #[test]
    fn any_arbitrary_domain_can_be_governed_without_code_changes() {
        // The whole point of the registry redesign: a brand-new/internal AI
        // tool needs only a policy entry, never a code change.
        let config = PolicyConfig {
            applications: vec![ApplicationPolicy {
                id: "internal-llm-tool".to_string(),
                match_domains: vec!["llm.internal.example.com".to_string()],
                enabled: true,
                upload: false,
                prompt_scan: true,
                response_scan: true,
                connect_proxy: false,
            }],
            ..PolicyConfig::default()
        };
        let app = config.resolve_application("llm.internal.example.com").expect("should resolve");
        assert_eq!(app.id, "internal-llm-tool");
        assert!(!app.upload);
    }

    #[test]
    fn upload_action_defaults_to_inspect_for_unconfigured_extensions() {
        let config = PolicyConfig::default();
        assert_eq!(config.upload_action("docx"), UploadAction::Inspect);
        assert_eq!(config.upload_action(".docx"), UploadAction::Inspect);
    }

    #[test]
    fn upload_action_respects_configured_block_and_allow() {
        let config = PolicyConfig {
            uploads: HashMap::from([
                ("zip".to_string(), UploadAction::Block),
                ("csv".to_string(), UploadAction::Allow),
            ]),
            ..PolicyConfig::default()
        };
        assert_eq!(config.upload_action("zip"), UploadAction::Block);
        assert_eq!(config.upload_action("ZIP"), UploadAction::Block, "extension match is case-insensitive");
        assert_eq!(config.upload_action("csv"), UploadAction::Allow);
    }

    #[test]
    fn policy_config_round_trips_through_json() {
        let config = PolicyConfig {
            applications: vec![ApplicationPolicy {
                id: "claude".to_string(),
                match_domains: vec!["anthropic.com".to_string()],
                enabled: true,
                upload: false,
                prompt_scan: true,
                response_scan: true,
                connect_proxy: false,
            }],
            uploads: HashMap::from([("zip".to_string(), UploadAction::Block)]),
            ..PolicyConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn connect_proxy_defaults_to_false_when_omitted() {
        // Real safety property, not just a serde nicety: an ordinary
        // hand-written/pre-existing application entry (added purely to
        // govern browser-extension upload/prompt_scan settings for a site
        // like chatgpt.com) must NOT silently opt into CONNECT-proxy MITM
        // just by existing -- see `ApplicationPolicy::connect_proxy`'s own
        // doc comment for why that would resurrect a real, already-fixed
        // bot-detection-blocking bug.
        let json = r#"{"id": "chatgpt", "match_domains": ["openai.com"], "enabled": true}"#;
        let app: ApplicationPolicy = serde_json::from_str(json).unwrap();
        assert!(!app.connect_proxy, "an application entry with no connect_proxy key must default to false");
    }

    #[test]
    fn connect_proxy_opt_in_round_trips_through_json() {
        let app = ApplicationPolicy {
            id: "internal-llm-tool".to_string(),
            match_domains: vec!["llm.internal.example.com".to_string()],
            enabled: true,
            upload: true,
            prompt_scan: true,
            response_scan: true,
            connect_proxy: true,
        };
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"connect_proxy\":true"));
        let parsed: ApplicationPolicy = serde_json::from_str(&json).unwrap();
        assert!(parsed.connect_proxy);
    }

    #[test]
    fn omitted_sections_fall_back_to_defaults() {
        // A minimal hand-written policy document (e.g. an admin only caring
        // about uploads) shouldn't need to spell out every section.
        let parsed: PolicyConfig = serde_json::from_str(r#"{"uploads": {"zip": "block"}}"#).unwrap();
        assert_eq!(parsed.upload_action("zip"), UploadAction::Block);
        assert_eq!(parsed.capabilities, CapabilityPolicy::default());
        assert_eq!(parsed.security, SecurityPolicy::default());
    }

    fn custom_finding(pattern: &str) -> Finding {
        Finding {
            category: FindingCategory::CustomKeyword,
            match_name: pattern.to_string(),
            snippet: pattern.to_string(),
            severity: "MEDIUM".to_string(),
            redacted_replacement: None,
        }
    }

    #[test]
    fn each_custom_keyword_rule_gets_its_own_action() {
        let config = PolicyConfig {
            custom_keywords: vec![
                CustomKeywordRule { pattern: "OurCompanyName".to_string(), action: Action::Redact, case_sensitive: false },
                CustomKeywordRule { pattern: "CompetitorX".to_string(), action: Action::Block, case_sensitive: false },
                CustomKeywordRule { pattern: "PublicProductName".to_string(), action: Action::Allow, case_sensitive: false },
            ],
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);
        assert_eq!(engine.evaluate(&[custom_finding("OurCompanyName")]), Action::Redact);
        assert_eq!(engine.evaluate(&[custom_finding("CompetitorX")]), Action::Block);
        assert_eq!(engine.evaluate(&[custom_finding("PublicProductName")]), Action::Allow);
    }

    #[test]
    fn custom_keyword_with_no_matching_rule_falls_back_to_category_default() {
        // Shouldn't normally happen (the scanner only ever produces a
        // CustomKeyword finding for a pattern that IS in the rule list),
        // but must degrade sensibly rather than panicking if it ever does.
        let engine = PolicyEngine::default();
        assert_eq!(engine.evaluate(&[custom_finding("SomeWordWithNoRule")]), Action::Redact); // category default
    }

    #[test]
    fn a_blocking_custom_keyword_outranks_a_redacting_pii_finding_in_the_same_batch() {
        let config = PolicyConfig {
            custom_keywords: vec![CustomKeywordRule { pattern: "CompetitorX".to_string(), action: Action::Block, case_sensitive: false }],
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);
        let action = engine.evaluate(&[finding(FindingCategory::Pii), custom_finding("CompetitorX")]);
        assert_eq!(action, Action::Block);
    }

    // ── SP-RISK-003: real policy engine (Detection → Risk → Rules → Policy → Action) ──

    #[test]
    fn evaluate_with_context_matches_evaluate_when_no_rules_are_configured() {
        // The core non-regression proof: an unconfigured PolicyConfig (every
        // existing test/call site) must get byte-identical output from the
        // new pipeline as the old one.
        let engine = PolicyEngine::default();
        let findings = [finding(FindingCategory::Secret), finding(FindingCategory::Pii)];
        let old = engine.evaluate(&findings);
        let new = engine.evaluate_with_context(&findings, &RiskContext::default());
        assert_eq!(old, new.action);
        assert!(new.matched_rules.is_empty());
    }

    #[test]
    fn evaluate_with_context_always_computes_a_risk_score() {
        let engine = PolicyEngine::default();
        let clean = engine.evaluate_with_context(&[], &RiskContext::default());
        assert_eq!(clean.risk.total, 0);

        let risky = engine.evaluate_with_context(&[finding(FindingCategory::Secret)], &RiskContext::default());
        assert!(risky.risk.total > 0);
    }

    #[test]
    fn a_configured_rule_can_escalate_the_category_lookup_result() {
        use safeprompt_rules::Condition;
        // Secret alone defaults to Redact (see default_policy_redacts_secrets
        // above) -- a rule adding "AND public AI app -> Block" should win.
        let config = PolicyConfig {
            rules: vec![Rule {
                name: "secret-to-public-llm-block".to_string(),
                condition: Condition::And(vec![Condition::CategoryDetected(FindingCategory::Secret), Condition::PublicAiApp]),
                action: Action::Block,
            }],
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);
        let findings = [finding(FindingCategory::Secret)];

        let public = engine.evaluate_with_context(&findings, &RiskContext { public_ai_app: true, ..RiskContext::default() });
        assert_eq!(public.action, Action::Block);
        assert_eq!(public.matched_rules, vec!["secret-to-public-llm-block".to_string()]);

        // Same findings, no public-app context -- rule doesn't fire, falls
        // back to the plain category lookup (Redact).
        let internal = engine.evaluate_with_context(&findings, &RiskContext::default());
        assert_eq!(internal.action, Action::Redact);
        assert!(internal.matched_rules.is_empty());
    }

    #[test]
    fn a_configured_rule_never_downgrades_the_category_lookup_result() {
        use safeprompt_rules::Condition;
        // PromptInjection defaults to Block. A matched rule saying Warn must
        // not weaken that -- worst-of, not last-rule-wins.
        let config = PolicyConfig {
            rules: vec![Rule { name: "warn-on-injection".to_string(), condition: Condition::CategoryDetected(FindingCategory::PromptInjection), action: Action::Warn }],
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);
        let decision = engine.evaluate_with_context(&[finding(FindingCategory::PromptInjection)], &RiskContext::default());
        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.matched_rules, vec!["warn-on-injection".to_string()]);
    }

    #[test]
    fn a_rule_can_key_off_the_risk_score_computed_in_the_same_call() {
        use safeprompt_rules::Condition;
        // Proves Risk actually feeds Rules within one evaluate_with_context
        // call, not just when a caller pre-computes and passes a score in.
        let config = PolicyConfig {
            rules: vec![Rule { name: "high-risk-block".to_string(), condition: Condition::RiskScoreAtLeast(30), action: Action::Block }],
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config);

        let low_risk = engine.evaluate_with_context(&[finding(FindingCategory::Pii)], &RiskContext::default());
        assert_ne!(low_risk.action, Action::Block);

        let high_risk = engine.evaluate_with_context(&[finding(FindingCategory::PromptInjection)], &RiskContext::default());
        assert!(high_risk.risk.total >= 30, "PromptInjection at MEDIUM severity should clear 30: got {}", high_risk.risk.total);
        assert_eq!(high_risk.action, Action::Block);
    }

    #[test]
    fn action_rank_orders_all_six_variants() {
        let ranked = [Action::Allow, Action::Audit, Action::Warn, Action::Redact, Action::RequireApproval, Action::Block];
        for pair in ranked.windows(2) {
            assert!(action_rank(&pair[0]) < action_rank(&pair[1]), "{:?} should outrank {:?}", pair[1], pair[0]);
        }
    }

    #[test]
    fn policy_config_with_rules_round_trips_through_json() {
        use safeprompt_rules::Condition;
        let config = PolicyConfig {
            rules: vec![Rule {
                name: "test-rule".to_string(),
                condition: Condition::And(vec![Condition::CategoryDetected(FindingCategory::Secret), Condition::PublicAiApp]),
                action: Action::Block,
            }],
            ..PolicyConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let round_tripped: PolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, round_tripped);
    }
}
