//! SP-RISK-001 — numeric risk engine.
//!
//! Every decision made today (`safeprompt-policy::PolicyEngine::evaluate`)
//! is a "worst finding wins" lookup: one `Block`-mapped finding always
//! outranks any number of weaker ones, and nothing outside `Finding` itself
//! (which application a prompt is headed to, whose device/account it came
//! from, how many prior violations they have) has any say in the outcome.
//! `task.md`'s own Phase 2 design note is explicit that this crate's job is
//! to *feed* that decision, not replace it yet: "Needs numeric scoring (PII
//! score + injection score + compliance score -> overall risk) feeding the
//! action decision, not replacing it." Composing conditional rules on top of
//! a score (`IF secret_detected AND ai_site = public_llm THEN mask`) is
//! SP-RISK-002; swapping `PolicyEngine::evaluate` itself over to consume
//! that output is SP-RISK-003. This crate deliberately stops at "produce a
//! trustworthy 0-100 number with an inspectable breakdown" — no call site
//! elsewhere in the agent is changed by adding it.
//!
//! Depends only on `safeprompt-common` (for `Finding`/`FindingCategory`), not
//! on `safeprompt-policy` — a risk score is a pure function of findings plus
//! request context, and the direction of the dependency needs to stay this
//! way round: `policy` (or whatever hosts SP-RISK-003's real policy engine)
//! will depend on `risk`, never the other way, or this crate would have to
//! know about `Action`/`SecurityPolicy` it has no business knowing about.

use safeprompt_common::{Finding, FindingCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Coarse human-facing banding over the numeric score — SP-RISK-003 (and any
/// UI/audit surface before it exists) needs *a* label to show a human, and
/// re-deriving the same four cutoffs at every call site would drift. Bounds
/// are inclusive on the low end, matching `RiskBand::from_score`.
///
/// `PartialOrd`/`Ord` derive from declaration order (`Low < Medium < High <
/// Critical`) — added so `safeprompt-rules` (SP-RISK-002) can express a
/// `RiskBandAtLeast(High)`-style rule condition without either crate
/// reimplementing a second ranking of the same four bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskBand {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=24 => RiskBand::Low,
            25..=49 => RiskBand::Medium,
            50..=74 => RiskBand::High,
            _ => RiskBand::Critical,
        }
    }
}

/// One line item in a score's breakdown — what contributed, and how much.
/// Exists so a score is never just an opaque number: an admin (or a future
/// audit/UI surface) can see *why* a request scored 62, the same way
/// `Finding` already explains *why* a category fired at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskSignal {
    pub name: String,
    pub points: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Clamped to 0..=100 — the sum of every `RiskSignal.points` before
    /// clamping is intentionally kept in `signals` unclamped, so a
    /// breakdown that summed to, say, 138 still shows its true contributors
    /// rather than lying about how far over the cap the request actually
    /// was.
    pub total: u8,
    pub band: RiskBand,
    pub signals: Vec<RiskSignal>,
}

/// Contextual signals `Finding`s alone can't carry — either because they
/// describe the *destination* of a request rather than its content
/// (`public_ai_app`), or because they describe history no single-request
/// scanner has visibility into (`*_previous_violations`, queried by the
/// caller from `safeprompt-storage` before constructing this). `file_sensitivity`
/// is a forward-looking hook: no file-sensitivity classifier exists yet
/// anywhere in the codebase (checked while building this — see
/// `agent/crates/file_inspector`, which only extracts text today), so it's
/// `Option` and contributes nothing when `None`, exactly as if the signal
/// didn't exist yet — a future classifier can start populating it with zero
/// change to this crate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskContext {
    /// True when the request's destination resolves to a governed
    /// application the tenant's policy doesn't treat as internal/trusted —
    /// in practice, `PolicyConfig::resolve_application(domain)` returning
    /// `Some(app)` with no internal/self-hosted marking. The caller decides
    /// this; this crate has no notion of domains or policy documents.
    pub public_ai_app: bool,
    pub device_previous_violations: u32,
    pub user_previous_violations: u32,
    /// 0-100 sensitivity of the file/document a finding was extracted from,
    /// if the caller has one. `None` = no classifier available (today,
    /// always).
    pub file_sensitivity: Option<u8>,
}

impl Default for RiskContext {
    fn default() -> Self {
        Self {
            public_ai_app: false,
            device_previous_violations: 0,
            user_previous_violations: 0,
            file_sensitivity: None,
        }
    }
}

/// Base points a single finding in this category contributes at `HIGH`
/// severity (the severity multiplier in `severity_multiplier` scales this up
/// or down). Ranking mirrors `safeprompt-policy::default_actions`'s own
/// judgment call of what's worse than what — `PromptInjection` outranks
/// `Secret` there (the only category that defaults to `Block` rather than
/// `Redact`) and does here too; `CustomKeyword` is tenant-defined and
/// deliberately mid-weighted since it can mean anything from a competitor
/// name to a company codename.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskWeights {
    pub category: HashMap<FindingCategory, u32>,
    /// Flat points for a request headed to a public/ungoverned AI
    /// application (`RiskContext::public_ai_app`).
    pub public_ai_app: u32,
    /// Points per prior violation (device + user combined), before capping.
    pub per_prior_violation: u32,
    /// Hard cap on the total contribution from prior-violation history, so
    /// one chronically-flagged device/user can't alone saturate the score
    /// regardless of what the current request actually contains.
    pub max_violation_points: u32,
    /// Fraction of `RiskContext::file_sensitivity` (0-100) that carries
    /// through into the score, e.g. `0.15` turns a maximally-sensitive file
    /// (100) into +15 points.
    pub file_sensitivity_weight: f32,
    /// Per-category diminishing-returns factor for the 2nd, 3rd, ...
    /// finding in the *same* category on one request: contribution of the
    /// (n+1)th finding (0-indexed) is multiplied by
    /// `1.0 / (1.0 + repeat_decay * n)`. Without this, ten low-confidence
    /// hits of the same regex on one long prompt would swamp the score far
    /// more than the underlying risk actually grew — the first hit already
    /// told the policy layer "this category is present"; the ninth adds far
    /// less new information.
    pub repeat_decay: f32,
}

fn default_category_weights() -> HashMap<FindingCategory, u32> {
    use FindingCategory::*;
    HashMap::from([
        (PromptInjection, 45),
        (Secret, 40),
        (Financial, 35),
        (Pii, 25),
        // Same base weight as PromptInjection -- severity_multiplier still
        // does the real differentiation (CRITICAL threats/self-harm at
        // 1.25x vs. LOW profanity at 0.5x), same as every other category
        // here. A high base weight matters because this is the one
        // category where the *policy* action (Warn, see
        // safeprompt-policy::default_actions) is deliberately not severity-
        // aware -- the risk score is what lets a tenant-authored Rule
        // Engine rule react to the severe end without waiting on that.
        (Toxicity, 45),
        (CustomKeyword, 20),
        (Internal, 20),
    ])
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            category: default_category_weights(),
            public_ai_app: 10,
            per_prior_violation: 3,
            max_violation_points: 15,
            file_sensitivity_weight: 0.15,
            repeat_decay: 0.5,
        }
    }
}

/// `Finding::severity` is free-text (`"LOW"/"MEDIUM"/"HIGH"/"CRITICAL"`, see
/// `safeprompt-common::Finding`'s own doc comment) rather than a typed enum
/// — matching that rather than adding a parallel typed severity here.
/// Unrecognized text (defensive only; every scanner in this codebase emits
/// one of the four) is treated as `MEDIUM` rather than panicking or zeroing
/// out the finding's contribution entirely.
fn severity_multiplier(severity: &str) -> f32 {
    match severity.to_ascii_uppercase().as_str() {
        "LOW" => 0.5,
        "HIGH" => 1.0,
        "CRITICAL" => 1.25,
        _ => 0.75, // MEDIUM, and any unrecognized value
    }
}

pub struct RiskEngine {
    weights: RiskWeights,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new(RiskWeights::default())
    }
}

impl RiskEngine {
    pub fn new(weights: RiskWeights) -> Self {
        Self { weights }
    }

    pub fn weights(&self) -> &RiskWeights {
        &self.weights
    }

    /// Scores one request's findings plus its context. Order-independent in
    /// `findings` except for which occurrence of a repeated category is
    /// "first" for `repeat_decay` purposes — callers pass findings in scan
    /// order, same as `PolicyEngine::evaluate` already assumes.
    pub fn score(&self, findings: &[Finding], context: &RiskContext) -> RiskScore {
        let mut signals = Vec::new();
        let mut seen_in_category: HashMap<&FindingCategory, u32> = HashMap::new();

        for finding in findings {
            let base = *self.weights.category.get(&finding.category).unwrap_or(&20) as f32;
            let occurrence = seen_in_category.entry(&finding.category).or_insert(0);
            let decay = 1.0 / (1.0 + self.weights.repeat_decay * (*occurrence as f32));
            *occurrence += 1;

            let points = (base * severity_multiplier(&finding.severity) * decay).round() as i32;
            signals.push(RiskSignal {
                name: format!("{:?} finding ({}): {}", finding.category, finding.severity, finding.match_name),
                points,
            });
        }

        if context.public_ai_app {
            signals.push(RiskSignal { name: "destination is a public/ungoverned AI application".to_string(), points: self.weights.public_ai_app as i32 });
        }

        let prior_violations = context.device_previous_violations.saturating_add(context.user_previous_violations);
        if prior_violations > 0 {
            let points = (prior_violations * self.weights.per_prior_violation).min(self.weights.max_violation_points) as i32;
            signals.push(RiskSignal { name: format!("{prior_violations} prior violation(s) on this device/user"), points });
        }

        if let Some(sensitivity) = context.file_sensitivity {
            let points = (sensitivity as f32 * self.weights.file_sensitivity_weight).round() as i32;
            if points != 0 {
                signals.push(RiskSignal { name: format!("source file sensitivity ({sensitivity}/100)"), points });
            }
        }

        let raw_total: i32 = signals.iter().map(|s| s.points).sum();
        let total = raw_total.clamp(0, 100) as u8;

        RiskScore { total, band: RiskBand::from_score(total), signals }
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

    #[test]
    fn no_findings_no_context_scores_zero() {
        let engine = RiskEngine::default();
        let score = engine.score(&[], &RiskContext::default());
        assert_eq!(score.total, 0);
        assert_eq!(score.band, RiskBand::Low);
        assert!(score.signals.is_empty());
    }

    #[test]
    fn single_high_secret_lands_in_medium_band() {
        let engine = RiskEngine::default();
        let score = engine.score(&[finding(FindingCategory::Secret, "HIGH")], &RiskContext::default());
        // 40 (Secret base) * 1.0 (HIGH) = 40
        assert_eq!(score.total, 40);
        assert_eq!(score.band, RiskBand::Medium);
    }

    #[test]
    fn severity_scales_the_same_category_up_and_down() {
        let engine = RiskEngine::default();
        let low = engine.score(&[finding(FindingCategory::Pii, "LOW")], &RiskContext::default());
        let critical = engine.score(&[finding(FindingCategory::Pii, "CRITICAL")], &RiskContext::default());
        assert!(critical.total > low.total);
    }

    #[test]
    fn prompt_injection_outweighs_pii_at_equal_severity() {
        let engine = RiskEngine::default();
        let injection = engine.score(&[finding(FindingCategory::PromptInjection, "HIGH")], &RiskContext::default());
        let pii = engine.score(&[finding(FindingCategory::Pii, "HIGH")], &RiskContext::default());
        assert!(injection.total > pii.total);
    }

    #[test]
    fn repeated_findings_in_one_category_diminish() {
        let engine = RiskEngine::default();
        let one = engine.score(&[finding(FindingCategory::Pii, "HIGH")], &RiskContext::default());
        let five = engine.score(
            &vec![finding(FindingCategory::Pii, "HIGH"); 5],
            &RiskContext::default(),
        );
        // Five hits score higher than one, but nowhere near 5x — diminishing
        // returns, not linear stacking.
        assert!(five.total > one.total);
        assert!((five.total as u32) < one.total as u32 * 5);
    }

    #[test]
    fn multiple_categories_compound() {
        let engine = RiskEngine::default();
        let secret_only = engine.score(&[finding(FindingCategory::Secret, "HIGH")], &RiskContext::default());
        let both = engine.score(
            &[finding(FindingCategory::Secret, "HIGH"), finding(FindingCategory::Pii, "HIGH")],
            &RiskContext::default(),
        );
        assert!(both.total > secret_only.total);
    }

    #[test]
    fn public_ai_app_adds_flat_points() {
        let engine = RiskEngine::default();
        let internal = engine.score(&[], &RiskContext::default());
        let public = engine.score(&[], &RiskContext { public_ai_app: true, ..RiskContext::default() });
        assert_eq!(public.total - internal.total, 10);
    }

    #[test]
    fn prior_violations_are_capped() {
        let engine = RiskEngine::default();
        let capped = engine.score(
            &[],
            &RiskContext { device_previous_violations: 50, user_previous_violations: 50, ..RiskContext::default() },
        );
        // per_prior_violation=3, max_violation_points=15 -- 100 violations
        // would be 300 uncapped, must clamp to 15.
        let violation_signal = capped.signals.iter().find(|s| s.name.contains("prior violation")).unwrap();
        assert_eq!(violation_signal.points, 15);
    }

    #[test]
    fn file_sensitivity_none_contributes_nothing() {
        let engine = RiskEngine::default();
        let score = engine.score(&[], &RiskContext { file_sensitivity: None, ..RiskContext::default() });
        assert!(score.signals.is_empty());
    }

    #[test]
    fn file_sensitivity_scales_with_weight() {
        let engine = RiskEngine::default();
        let score = engine.score(&[], &RiskContext { file_sensitivity: Some(100), ..RiskContext::default() });
        // 100 * 0.15 = 15
        assert_eq!(score.total, 15);
    }

    #[test]
    fn total_never_exceeds_100_even_when_everything_fires() {
        let engine = RiskEngine::default();
        let many_findings: Vec<Finding> = [
            FindingCategory::Secret,
            FindingCategory::PromptInjection,
            FindingCategory::Pii,
            FindingCategory::Financial,
            FindingCategory::Internal,
            FindingCategory::CustomKeyword,
        ]
        .into_iter()
        .flat_map(|c| std::iter::repeat_with(move || finding(c.clone(), "CRITICAL")).take(4))
        .collect();
        let score = engine.score(
            &many_findings,
            &RiskContext { public_ai_app: true, device_previous_violations: 20, user_previous_violations: 20, file_sensitivity: Some(100) },
        );
        assert_eq!(score.total, 100);
        assert_eq!(score.band, RiskBand::Critical);
        // The breakdown still reflects the true (unclamped) sum of
        // contributors, not a lie that everything totalled exactly 100.
        let raw_total: i32 = score.signals.iter().map(|s| s.points).sum();
        assert!(raw_total > 100);
    }

    #[test]
    fn band_boundaries() {
        assert_eq!(RiskBand::from_score(0), RiskBand::Low);
        assert_eq!(RiskBand::from_score(24), RiskBand::Low);
        assert_eq!(RiskBand::from_score(25), RiskBand::Medium);
        assert_eq!(RiskBand::from_score(49), RiskBand::Medium);
        assert_eq!(RiskBand::from_score(50), RiskBand::High);
        assert_eq!(RiskBand::from_score(74), RiskBand::High);
        assert_eq!(RiskBand::from_score(75), RiskBand::Critical);
        assert_eq!(RiskBand::from_score(100), RiskBand::Critical);
    }

    #[test]
    fn custom_weights_are_respected() {
        let mut weights = RiskWeights::default();
        weights.category.insert(FindingCategory::Pii, 90);
        let engine = RiskEngine::new(weights);
        let score = engine.score(&[finding(FindingCategory::Pii, "HIGH")], &RiskContext::default());
        assert_eq!(score.total, 90);
    }
}
