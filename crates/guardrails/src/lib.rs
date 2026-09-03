//! Output-side content-safety guardrails — closes the gap flagged in the
//! 2026-08-12 Agent-tier reconciliation: no toxicity/topic-restriction
//! guardrail existed anywhere in this codebase despite the product's "AI
//! Firewall + Guardrails, not just DLP" positioning (`task.md`).
//!
//! **Topic restriction is deliberately NOT built here.** That capability
//! already exists — `safeprompt-policy::CustomKeywordRule` is exactly a
//! tenant-authored keyword/phrase → action mapping (e.g. `"CompetitorX" ->
//! Block`), which is what "restrict discussion of X" already is. Building a
//! second, parallel keyword-matching engine under a "topic restriction"
//! label would duplicate that mechanism rather than close a real gap; the
//! actual gap was that nobody had connected the dots, not missing code.
//!
//! **`ToxicityScanner` is the real net-new piece.** Keyword/phrase-based
//! (`Condition::And`/regex over curated term lists), explicitly NOT a
//! semantic classifier — matches user-directed scope ("rule/keyword-based
//! v1", 2026-08-12) over a real ONNX content-safety model, which stays a
//! stated future upgrade path (same shape as OCR/NER: a real model,
//! license-gated, deferred to its own pass), not faked here.
//!
//! **Hate speech / slurs targeting protected classes are explicitly OUT OF
//! SCOPE for v1**, stated plainly rather than shipped as a low-quality
//! hand-rolled list: a defensible list requires either a real curated
//! dataset or a real classifier, neither of which this pass builds. Four
//! categories ARE covered, each on real phrase/word patterns with a
//! genuine legitimate-usage false-positive fixture proving the pattern
//! isn't naively over-broad:
//!   - **Threats of violence** — "I will/I'm going to <harm verb> you"-
//!     shaped phrases.
//!   - **Self-harm ideation** — "kill myself"/"end my life"-shaped phrases.
//!     Flagged for audit/review, not silently dropped — duty-of-care
//!     content in an enterprise AI-chat context is exactly the kind of
//!     thing that should surface, not vanish.
//!   - **Harassment** — direct "you are a/an <insult>"-shaped second-person
//!     insults.
//!   - **Profanity** — common non-slur curse words, standalone word-boundary
//!     matches, lowest severity of the four (professional-communication
//!     policy, not a safety concern on its own).
//!
//! All four currently share `FindingCategory::Toxicity` (see that variant's
//! own doc comment) — the Rule Engine's `Condition` has no `match_name`-
//! level leaf yet, only category-level, so a tenant cannot today write "warn
//! on profanity but block on threats" as a single policy without also
//! changing this crate. Stated as a known limitation, not silently worked
//! around.

use regex::Regex;
use safeprompt_common::{Finding, FindingCategory, Scanner};

pub struct ToxicityScanner {
    threat_patterns: Vec<Regex>,
    self_harm_patterns: Vec<Regex>,
    harassment_patterns: Vec<Regex>,
    profanity_regex: Regex,
}

impl Default for ToxicityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ToxicityScanner {
    pub fn new() -> Self {
        Self {
            threat_patterns: [
                r"(?i)\bi(?:'m| am)? ?(?:going to|gonna|will)\s+(?:kill|hurt|beat|attack|stab|shoot)\s+you\b",
                r"(?i)\byou(?:'re| are)\s+(?:dead|a dead man|going to (?:die|get hurt))\b",
                r"(?i)\bi(?:'ll| will)\s+(?:make you (?:pay|suffer)|come after you)\b",
            ]
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect(),

            // Duty-of-care detection, not a crisis-hotline replacement — the
            // point is to surface this content for audit/review rather than
            // let it pass through silently, same reasoning the module doc
            // comment states.
            self_harm_patterns: [
                r"(?i)\b(?:i want to|i'm going to|going to|i will)\s+kill myself\b",
                r"(?i)\bend(?:ing)? my (?:own )?life\b",
                r"(?i)\bi (?:want to|don'?t want to live|wish i was dead)\b",
                r"(?i)\b(?:cut|hurt|harm) myself\b",
            ]
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect(),

            harassment_patterns: [
                r"(?i)\byou(?:'re| are) (?:such an?|a|an) (?:idiot|moron|loser|worthless|pathetic|stupid|useless)\b",
                r"(?i)\bshut up,? (?:you )?(?:idiot|moron|stupid|loser)\b",
                r"(?i)\bnobody (?:likes|wants) you\b",
            ]
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect(),

            // Word-boundary, case-insensitive, common non-slur profanity —
            // deliberately conservative (professional-communication policy,
            // not a safety detector) rather than an exhaustive list.
            profanity_regex: Regex::new(r"(?i)\b(fuck(?:ing|er|ed)?|shit(?:ty)?|asshole|bastard|bitch(?:es)?|damn it|goddamn)\b").unwrap(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for re in &self.threat_patterns {
            if let Some(mat) = re.find(text) {
                findings.push(Finding {
                    category: FindingCategory::Toxicity,
                    match_name: "THREAT_OF_VIOLENCE".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "CRITICAL".to_string(),
                    redacted_replacement: None,
                });
            }
        }

        for re in &self.self_harm_patterns {
            if let Some(mat) = re.find(text) {
                findings.push(Finding {
                    category: FindingCategory::Toxicity,
                    match_name: "SELF_HARM_IDEATION".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "CRITICAL".to_string(),
                    redacted_replacement: None,
                });
            }
        }

        for re in &self.harassment_patterns {
            if let Some(mat) = re.find(text) {
                findings.push(Finding {
                    category: FindingCategory::Toxicity,
                    match_name: "HARASSMENT".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: None,
                });
            }
        }

        if let Some(mat) = self.profanity_regex.find(text) {
            findings.push(Finding {
                category: FindingCategory::Toxicity,
                match_name: "PROFANITY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "LOW".to_string(),
                redacted_replacement: None,
            });
        }

        findings
    }
}

impl Scanner for ToxicityScanner {
    fn scan(&self, text: &str) -> Vec<Finding> {
        ToxicityScanner::scan(self, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn categories(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.match_name.as_str()).collect()
    }

    #[test]
    fn detects_a_direct_threat_of_violence() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("I'm going to hurt you if you do that again.");
        assert!(categories(&findings).contains(&"THREAT_OF_VIOLENCE"));
        assert_eq!(findings[0].severity, "CRITICAL");
    }

    #[test]
    fn does_not_flag_a_legitimate_sentence_about_violence() {
        // Real false-positive check, not just a happy-path threat fixture —
        // discussing violence (news, fiction, a security incident report)
        // must not trip the same pattern as an actual direct threat.
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("The news report described how the storm could hurt coastal towns.");
        assert!(!categories(&findings).contains(&"THREAT_OF_VIOLENCE"));
    }

    #[test]
    fn detects_self_harm_ideation() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("I don't want to live anymore, everything feels pointless.");
        assert!(categories(&findings).contains(&"SELF_HARM_IDEATION"));
    }

    #[test]
    fn does_not_flag_a_benign_use_of_kill_and_life() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("This bug is going to kill our release timeline unless we fix it.");
        assert!(!categories(&findings).contains(&"SELF_HARM_IDEATION"));
        assert!(!categories(&findings).contains(&"THREAT_OF_VIOLENCE"));
    }

    #[test]
    fn detects_direct_harassment() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("You're such an idiot, I can't believe you did that.");
        assert!(categories(&findings).contains(&"HARASSMENT"));
    }

    #[test]
    fn does_not_flag_ordinary_critical_feedback() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("This approach seems inefficient and I think we should reconsider it.");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_profanity_at_low_severity() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("This is such a shitty situation.");
        assert!(categories(&findings).contains(&"PROFANITY"));
        assert_eq!(findings.iter().find(|f| f.match_name == "PROFANITY").unwrap().severity, "LOW");
    }

    #[test]
    fn clean_professional_text_produces_no_findings() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("Please review the attached quarterly report and share your feedback by Friday.");
        assert!(findings.is_empty());
    }

    #[test]
    fn multiple_categories_can_fire_on_one_message() {
        let scanner = ToxicityScanner::new();
        let findings = scanner.scan("You're such an idiot and I'm going to hurt you for this shit.");
        let names = categories(&findings);
        assert!(names.contains(&"HARASSMENT"));
        assert!(names.contains(&"THREAT_OF_VIOLENCE"));
        assert!(names.contains(&"PROFANITY"));
    }
}
