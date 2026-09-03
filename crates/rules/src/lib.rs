//! SP-RISK-002 — rule engine: composable conditional rules over detection
//! findings, [`safeprompt_risk`]'s SP-RISK-001 score, and request context,
//! each resolving to an `Action` when its condition is met. The ticket's own
//! worked example:
//!
//! ```text
//! IF
//!     secret_detected
//! AND
//!     ai_site = public_llm
//! THEN
//!     mask
//! ```
//!
//! ...is exactly `Rule { condition: And([CategoryDetected(Secret),
//! PublicAiApp]), action: Action::Redact, .. }` here — this codebase already
//! calls masking `Redact` (see `safeprompt-policy::default_actions`'s own
//! doc comment: "Masking is the better default... the sensitive value never
//! reaches the LLM either way"), so `Condition`/`Rule` reuse
//! `safeprompt_common::Action` rather than inventing a second word for the
//! same outcome. `Warn`/`Block`/`Allow` are equally valid `THEN` outcomes —
//! the ticket's `mask` is just the one example given.
//!
//! Depends on `safeprompt-common` and `safeprompt-risk`, deliberately NOT on
//! `safeprompt-policy` — same dependency-direction reasoning as the risk
//! crate's own doc comment: `policy` (SP-RISK-003's "real policy engine")
//! will depend on `rules`, never the other way round, so this crate can't
//! know about `PolicyConfig`/`SecurityPolicy`/`PolicyEngine` at all.
//!
//! Still out of scope here, same as `safeprompt-risk`: nothing outside this
//! crate consumes a `RuleEngine` yet beyond the thin pass-through wired into
//! `safeprompt-inspector` (`Inspector::evaluate_rules`/`with_rules`) — there
//! is no policy-document schema for authoring rules centrally yet, and
//! `PolicyEngine::evaluate` itself is untouched.
//! Swapping the actual Allow/Warn/Redact/Block decision over to consult
//! rules (and the risk score) is SP-RISK-003.

use safeprompt_common::{Action, Finding, FindingCategory};
use safeprompt_risk::{RiskBand, RiskContext, RiskScore};
use serde::{Deserialize, Serialize};

/// One boolean condition, composable into trees via `And`/`Or`/`Not`. Leaf
/// variants read from the same three inputs `RuleEngine::evaluate` takes:
/// the finding set, the risk context, and (optionally) an already-computed
/// `RiskScore`. A condition that needs `risk` but is evaluated with
/// `risk: None` is treated as **not matched** rather than an error or a
/// silent `true` — a rule referencing a risk score should never fire on the
/// absence of one, since that's indistinguishable from "the caller didn't
/// bother scoring risk" rather than "risk is verified low."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Condition {
    /// At least one finding of this category is present.
    CategoryDetected(FindingCategory),
    /// At least `n` findings of this category are present — for rules that
    /// only care once a category shows up repeatedly (e.g. "3+ secrets in
    /// one message"), not on the first hit.
    CategoryCountAtLeast(FindingCategory, usize),
    /// `RiskContext::public_ai_app` — the `ai_site = public_llm` half of the
    /// ticket's own example.
    PublicAiApp,
    RiskScoreAtLeast(u8),
    RiskBandAtLeast(RiskBand),
    DeviceViolationsAtLeast(u32),
    UserViolationsAtLeast(u32),
    /// Vacuously `true` for an empty list, matching the standard logical
    /// convention (an empty set of requirements is trivially satisfied).
    And(Vec<Condition>),
    /// `false` for an empty list — the dual of `And`'s vacuous truth.
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    pub fn matches(&self, findings: &[Finding], context: &RiskContext, risk: Option<&RiskScore>) -> bool {
        match self {
            Condition::CategoryDetected(category) => findings.iter().any(|f| f.category == *category),
            Condition::CategoryCountAtLeast(category, n) => {
                findings.iter().filter(|f| f.category == *category).count() >= *n
            }
            Condition::PublicAiApp => context.public_ai_app,
            Condition::RiskScoreAtLeast(min) => risk.is_some_and(|r| r.total >= *min),
            Condition::RiskBandAtLeast(min) => risk.is_some_and(|r| r.band >= *min),
            Condition::DeviceViolationsAtLeast(min) => context.device_previous_violations >= *min,
            Condition::UserViolationsAtLeast(min) => context.user_previous_violations >= *min,
            Condition::And(conditions) => conditions.iter().all(|c| c.matches(findings, context, risk)),
            Condition::Or(conditions) => conditions.iter().any(|c| c.matches(findings, context, risk)),
            Condition::Not(condition) => !condition.matches(findings, context, risk),
        }
    }
}

/// One tenant/admin-authored rule. `name` is free text for audit/UI display
/// only (not matched on, unlike `safeprompt-policy::CustomKeywordRule`'s
/// `pattern`) — nothing keys off it today.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub condition: Condition,
    pub action: Action,
}

/// Ranks `Action` worst-to-best. Deliberately duplicated from
/// `safeprompt-policy`'s own private `action_rank` (identical logic, kept in
/// sync by hand -- see that copy's own doc comment for the full reasoning
/// behind the ranking, extended 2026-08-10/SP-RISK-003 to all six variants)
/// rather than shared, because sharing it would require either this crate
/// depending on `policy` (backwards — see module doc) or promoting the
/// match out to `safeprompt-common` for two call sites.
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

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl Default for RuleEngine {
    /// No rules — same "starts empty, tenant/admin populates it" convention
    /// as `PolicyConfig::custom_keywords`/`applications`. A `RuleEngine`
    /// with no rules matches nothing and every `evaluate` call returns
    /// `None`, same observable effect as not having a rule engine at all.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Every rule whose condition is satisfied, in configured order — for a
    /// caller that wants to show *which* rules fired (audit/UI), not just
    /// the resulting action.
    pub fn matched_rules(&self, findings: &[Finding], context: &RiskContext, risk: Option<&RiskScore>) -> Vec<&Rule> {
        self.rules.iter().filter(|rule| rule.condition.matches(findings, context, risk)).collect()
    }

    /// Worst-of across every matched rule's action — same "worst wins"
    /// convention `safeprompt-policy::PolicyEngine::evaluate` already uses
    /// across findings, applied here across rules instead. `None` when no
    /// rule matched at all; the caller (eventually `PolicyEngine`, per
    /// SP-RISK-003) decides what "no rule fired" means, same as
    /// `PolicyConfig::resolve_application` returning `None` for an
    /// unmatched domain today.
    pub fn evaluate(&self, findings: &[Finding], context: &RiskContext, risk: Option<&RiskScore>) -> Option<Action> {
        self.matched_rules(findings, context, risk)
            .into_iter()
            .map(|rule| rule.action.clone())
            .max_by_key(|action| action_rank(action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: FindingCategory, severity: &str) -> Finding {
        Finding {
            category,
            match_name: "test".to_string(),
            snippet: "snippet".to_string(),
            severity: severity.to_string(),
            redacted_replacement: None,
        }
    }

    fn public_ctx() -> RiskContext {
        RiskContext { public_ai_app: true, ..RiskContext::default() }
    }

    #[test]
    fn empty_engine_matches_nothing() {
        let engine = RuleEngine::default();
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Secret, "HIGH")], &public_ctx(), None), None);
    }

    #[test]
    fn ticket_worked_example_secret_and_public_llm_masks() {
        let rule = Rule {
            name: "secret-to-public-llm".to_string(),
            condition: Condition::And(vec![Condition::CategoryDetected(FindingCategory::Secret), Condition::PublicAiApp]),
            action: Action::Redact,
        };
        let engine = RuleEngine::new(vec![rule]);
        let findings = [finding(FindingCategory::Secret, "HIGH")];

        assert_eq!(engine.evaluate(&findings, &public_ctx(), None), Some(Action::Redact));
        // AND requires BOTH -- an internal (non-public) destination must not fire it.
        assert_eq!(engine.evaluate(&findings, &RiskContext::default(), None), None);
        // AND requires BOTH -- a public destination with no secret must not fire it either.
        assert_eq!(engine.evaluate(&[], &public_ctx(), None), None);
    }

    #[test]
    fn or_matches_if_either_side_does() {
        let rule = Rule {
            name: "secret-or-pii".to_string(),
            condition: Condition::Or(vec![
                Condition::CategoryDetected(FindingCategory::Secret),
                Condition::CategoryDetected(FindingCategory::Pii),
            ]),
            action: Action::Warn,
        };
        let engine = RuleEngine::new(vec![rule]);
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Pii, "LOW")], &RiskContext::default(), None), Some(Action::Warn));
        assert_eq!(engine.evaluate(&[finding(FindingCategory::Internal, "LOW")], &RiskContext::default(), None), None);
    }

    #[test]
    fn not_inverts_a_condition() {
        let rule = Rule {
            name: "block-if-not-public".to_string(),
            condition: Condition::Not(Box::new(Condition::PublicAiApp)),
            action: Action::Block,
        };
        let engine = RuleEngine::new(vec![rule]);
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), None), Some(Action::Block));
        assert_eq!(engine.evaluate(&[], &public_ctx(), None), None);
    }

    #[test]
    fn category_count_requires_the_threshold() {
        let rule = Rule {
            name: "repeated-secrets".to_string(),
            condition: Condition::CategoryCountAtLeast(FindingCategory::Secret, 3),
            action: Action::Block,
        };
        let engine = RuleEngine::new(vec![rule]);
        let two = [finding(FindingCategory::Secret, "HIGH"), finding(FindingCategory::Secret, "HIGH")];
        let three = [
            finding(FindingCategory::Secret, "HIGH"),
            finding(FindingCategory::Secret, "HIGH"),
            finding(FindingCategory::Secret, "HIGH"),
        ];
        assert_eq!(engine.evaluate(&two, &RiskContext::default(), None), None);
        assert_eq!(engine.evaluate(&three, &RiskContext::default(), None), Some(Action::Block));
    }

    #[test]
    fn risk_score_condition_requires_risk_to_be_supplied() {
        let rule = Rule { name: "high-risk".to_string(), condition: Condition::RiskScoreAtLeast(50), action: Action::Block };
        let engine = RuleEngine::new(vec![rule]);

        // No risk supplied at all -- must not match, not silently pass.
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), None), None);

        let low = RiskScore { total: 10, band: RiskBand::Low, signals: vec![] };
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), Some(&low)), None);

        let high = RiskScore { total: 60, band: RiskBand::High, signals: vec![] };
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), Some(&high)), Some(Action::Block));
    }

    #[test]
    fn risk_score_condition_composes_with_a_real_risk_engine() {
        // Sanity check against the actual SP-RISK-001 engine, not just a
        // hand-built RiskScore -- proves the two crates compose end to end.
        let rule = Rule { name: "high-risk".to_string(), condition: Condition::RiskScoreAtLeast(35), action: Action::Block };
        let engine = RuleEngine::new(vec![rule]);
        let real_score = safeprompt_risk::RiskEngine::default()
            .score(&[finding(FindingCategory::Secret, "CRITICAL")], &RiskContext::default());
        assert!(real_score.total >= 35, "a CRITICAL secret should clear the threshold: got {}", real_score.total);
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), Some(&real_score)), Some(Action::Block));
    }

    #[test]
    fn risk_band_condition_uses_band_ordering() {
        let rule = Rule { name: "at-least-high".to_string(), condition: Condition::RiskBandAtLeast(RiskBand::High), action: Action::Block };
        let engine = RuleEngine::new(vec![rule]);
        let medium = RiskScore { total: 40, band: RiskBand::Medium, signals: vec![] };
        let critical = RiskScore { total: 90, band: RiskBand::Critical, signals: vec![] };
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), Some(&medium)), None);
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), Some(&critical)), Some(Action::Block));
    }

    #[test]
    fn violation_history_thresholds() {
        let rule = Rule {
            name: "repeat-offender".to_string(),
            condition: Condition::Or(vec![Condition::DeviceViolationsAtLeast(3), Condition::UserViolationsAtLeast(3)]),
            action: Action::Warn,
        };
        let engine = RuleEngine::new(vec![rule]);
        let clean = RiskContext::default();
        let flagged = RiskContext { user_previous_violations: 3, ..RiskContext::default() };
        assert_eq!(engine.evaluate(&[], &clean, None), None);
        assert_eq!(engine.evaluate(&[], &flagged, None), Some(Action::Warn));
    }

    #[test]
    fn multiple_matching_rules_return_the_worst_action() {
        let rules = vec![
            Rule { name: "warn-on-pii".to_string(), condition: Condition::CategoryDetected(FindingCategory::Pii), action: Action::Warn },
            Rule { name: "block-on-injection".to_string(), condition: Condition::CategoryDetected(FindingCategory::PromptInjection), action: Action::Block },
        ];
        let engine = RuleEngine::new(rules);
        let findings = [finding(FindingCategory::Pii, "LOW"), finding(FindingCategory::PromptInjection, "HIGH")];
        assert_eq!(engine.evaluate(&findings, &RiskContext::default(), None), Some(Action::Block));

        let matched = engine.matched_rules(&findings, &RiskContext::default(), None);
        assert_eq!(matched.len(), 2, "both rules should be reported as matched, not just the winner");
    }

    #[test]
    fn empty_and_is_vacuously_true_empty_or_is_false() {
        let all_true = Rule { name: "empty-and".to_string(), condition: Condition::And(vec![]), action: Action::Warn };
        let all_false = Rule { name: "empty-or".to_string(), condition: Condition::Or(vec![]), action: Action::Block };
        let engine = RuleEngine::new(vec![all_true, all_false]);
        assert_eq!(engine.evaluate(&[], &RiskContext::default(), None), Some(Action::Warn));
    }
}
