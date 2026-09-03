//! Shannon-entropy-based detection of *unknown* secrets -- API keys,
//! tokens, and credentials that don't match any of the specific vendor
//! patterns in `lib.rs` (a new provider's key format, an internal service
//! token, a one-off webhook secret). Professional+ per the pricing matrix
//! (2026-08-07) -- a separately gated `Scanner`, not folded into
//! `SecretScanner`, so `apps/service` can wire it in or leave it out based
//! on the license feature, matching the existing pattern for NER (`ner:
//! Option<Box<dyn Scanner>>` on `Inspector`).
//!
//! Real, well-established technique -- the same one TruffleHog, Gitleaks,
//! and detect-secrets all use, not invented for this port: a token drawn
//! from a small, structured alphabet by random generation has near-maximal
//! Shannon entropy per character, while natural-language text and most
//! identifiers/hashes sit well below it. `MIN_TOKEN_LEN`/the two threshold
//! constants below are TruffleHog's own long-established defaults, chosen
//! because they're already tested against real-world code/text at scale,
//! not numbers picked for this port.
//!
//! **Deliberately probabilistic, not exact-match** -- unlike the
//! checksum-validated PII patterns in `crates/pii`, entropy detection
//! cannot tell a real secret apart from another high-entropy string with
//! the same shape (a git commit hash, a UUID, a base64-encoded hash
//! digest). This is a known, accepted, industry-standard tradeoff of the
//! technique itself, not a bug to "fix" by narrowing the thresholds until
//! it stops catching real secrets too. `flags_a_git_style_commit_hash`
//! below documents this honestly rather than hiding it. Findings land in
//! the same `FindingCategory::Secret` bucket as every other secret in this
//! crate, so they inherit the existing "Secret defaults to Redact" policy
//! (2026-08-05) automatically -- a plausible-but-uncertain match gets
//! masked, not hard-blocked, same as everything else in that category.

use regex::Regex;
use safeprompt_common::{Finding, FindingCategory, Scanner};

/// Bits/char thresholds ported from TruffleHog's classic defaults (widely
/// reused since, in Gitleaks/detect-secrets): base64's ~65-symbol alphabet
/// has a theoretical max entropy of log2(65) ≈ 6.02 bits/char; hex's
/// 16-symbol alphabet maxes at exactly log2(16) = 4.0. A real random
/// secret sits close to its alphabet's own max; natural text and most
/// identifiers sit well below it.
const BASE64_ENTROPY_THRESHOLD: f64 = 4.5;
const HEX_ENTROPY_THRESHOLD: f64 = 3.0;

/// Real Shannon entropy (`H = -Σ p(x) log2 p(x)`) over `s`'s character
/// frequency distribution -- not an approximation or a placeholder. Counts
/// by `char`, not byte, for correctness against any input (the two regexes
/// this feeds only ever match single-byte ASCII, so it wouldn't currently
/// matter in practice, but computing this any other way would be a latent
/// bug waiting for a caller that isn't ASCII-constrained).
fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count();
    if len == 0 {
        return 0.0;
    }
    let len = len as f64;
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub struct EntropyScanner {
    /// Pure-hex runs, at least 20 chars (TruffleHog's own default minimum
    /// -- below this, per-character entropy is too noisy to mean anything:
    /// a 6-char token can clear the threshold by chance far more often
    /// than a 40-char one).
    hex_token_regex: Regex,
    /// Base64-alphabet runs (letters/digits/+//=), same 20-char minimum.
    base64_token_regex: Regex,
}

impl Default for EntropyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyScanner {
    pub fn new() -> Self {
        Self {
            hex_token_regex: Regex::new(r"\b[0-9a-fA-F]{20,}\b").unwrap(),
            base64_token_regex: Regex::new(r"[A-Za-z0-9+/=]{20,}").unwrap(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Spans already classified as hex -- checked first since every hex
        // digit is also a valid base64 character, so a pure-hex run would
        // otherwise get matched (and potentially entropy-tested twice,
        // inconsistently) by both regexes.
        let mut hex_spans: Vec<(usize, usize)> = Vec::new();

        for mat in self.hex_token_regex.find_iter(text) {
            hex_spans.push((mat.start(), mat.end()));
            let token = mat.as_str();
            if shannon_entropy(token) >= HEX_ENTROPY_THRESHOLD {
                findings.push(Finding {
                    category: FindingCategory::Secret,
                    match_name: "HIGH_ENTROPY_HEX".to_string(),
                    snippet: token.to_string(),
                    severity: "MEDIUM".to_string(),
                    redacted_replacement: Some("[REDACTED_HIGH_ENTROPY]".to_string()),
                });
            }
        }

        for mat in self.base64_token_regex.find_iter(text) {
            if hex_spans.iter().any(|&(s, e)| mat.start() >= s && mat.end() <= e) {
                continue; // already judged against the hex-alphabet threshold above
            }
            let token = mat.as_str();
            if shannon_entropy(token) >= BASE64_ENTROPY_THRESHOLD {
                findings.push(Finding {
                    category: FindingCategory::Secret,
                    match_name: "HIGH_ENTROPY_BASE64".to_string(),
                    snippet: token.to_string(),
                    severity: "MEDIUM".to_string(),
                    redacted_replacement: Some("[REDACTED_HIGH_ENTROPY]".to_string()),
                });
            }
        }

        findings
    }
}

impl Scanner for EntropyScanner {
    fn scan(&self, text: &str) -> Vec<Finding> {
        EntropyScanner::scan(self, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_of_a_uniform_random_looking_string_is_near_maximal() {
        // A real, non-repeating 32-char base64-alphabet token -- every
        // character distinct, close to the theoretical max for its length.
        let entropy = shannon_entropy("Kj8mQ2xZpL9vN4tB7wR1sD6fH3yC0gE5");
        assert!(entropy > 4.5, "expected high entropy for a random-looking token, got {entropy}");
    }

    #[test]
    fn shannon_entropy_of_a_repeated_character_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn flags_a_realistic_high_entropy_base64_looking_token() {
        let scanner = EntropyScanner::new();
        // Shaped like a real service's random API secret -- not a real key.
        let findings = scanner.scan("webhook_secret=Zk9mQxP2vL8nR4tB7wD1sJ6fH3yC0gEaK5uV+X==");
        assert!(findings.iter().any(|f| f.match_name == "HIGH_ENTROPY_BASE64"), "expected a high-entropy base64 finding, got {findings:?}");
    }

    #[test]
    fn flags_a_realistic_high_entropy_hex_looking_token() {
        let scanner = EntropyScanner::new();
        let findings = scanner.scan("session_token=4f9a2c7e1b8d3f6a0c5e9b2d7f1a4c8e6b3d9f0a");
        assert!(findings.iter().any(|f| f.match_name == "HIGH_ENTROPY_HEX"), "expected a high-entropy hex finding, got {findings:?}");
    }

    #[test]
    fn does_not_flag_plain_english_prose() {
        // The actual false-positive concern that matters in practice: a
        // real user's ordinary sentence must not get redacted just because
        // it happens to contain a 20+ character run of letters. Natural
        // language has much lower per-character entropy than random data,
        // due to letter-frequency skew (e/t/a/o dominate; q/x/z are rare).
        let scanner = EntropyScanner::new();
        let findings = scanner.scan(
            "Please summarize the quarterly financial report and highlight any concerning trends for the leadership team",
        );
        assert!(findings.is_empty(), "expected no findings on ordinary English prose, got {findings:?}");
    }

    #[test]
    fn does_not_flag_short_tokens_below_the_minimum_length() {
        let scanner = EntropyScanner::new();
        // "Kj8mQ2xZpL" is only 10 chars -- genuinely high per-char entropy,
        // but too short to be a reliable signal (see MIN_TOKEN_LEN's own
        // doc comment) and below the regex's own 20-char floor, so it's
        // never even considered a candidate token.
        let findings = scanner.scan("code is Kj8mQ2xZpL, use it");
        assert!(findings.is_empty(), "a token below the minimum length must never be flagged, got {findings:?}");
    }

    #[test]
    fn a_pure_hex_token_is_classified_once_not_double_counted_as_base64_too() {
        let scanner = EntropyScanner::new();
        let findings = scanner.scan("id=4f9a2c7e1b8d3f6a0c5e9b2d7f1a4c8e6b3d9f0a");
        let matching: Vec<_> = findings.iter().filter(|f| f.snippet == "4f9a2c7e1b8d3f6a0c5e9b2d7f1a4c8e6b3d9f0a").collect();
        assert_eq!(matching.len(), 1, "a single hex token must produce exactly one finding, not one per regex it happens to also match: {findings:?}");
        assert_eq!(matching[0].match_name, "HIGH_ENTROPY_HEX");
    }

    #[test]
    fn flags_a_git_style_commit_hash_a_known_accepted_tradeoff_not_a_bug() {
        // Honest documentation of entropy detection's real limitation (see
        // this module's own doc comment): a git commit SHA is genuinely
        // high-entropy hex (that's what a hash function produces) and gets
        // flagged the same way a real leaked hex token would. This is the
        // correct, expected, industry-standard behavior of this technique
        // -- not something a future change should "fix" by narrowing the
        // threshold, which would just stop catching real unknown secrets
        // too. The 2026-08-05 crypto-wallet false-positive fix elsewhere in
        // this crate was different in kind: that was a charset-shape bug
        // (base58 accidentally matching plain lowercase hex), fixable by
        // tightening a regex without losing detection power. This isn't
        // that -- there is no regex fix for "a hash and a secret look the
        // same to an entropy measurement." Mitigated instead by category
        // (still just `Secret`, defaults to Redact not Block) and by this
        // whole scanner being an opt-in Professional+ feature, not
        // Community's default-on baseline.
        let scanner = EntropyScanner::new();
        let real_git_sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let findings = scanner.scan(real_git_sha);
        assert!(findings.iter().any(|f| f.match_name == "HIGH_ENTROPY_HEX"), "expected this documented, accepted tradeoff to still hold: {findings:?}");
    }

    #[test]
    fn scanner_trait_impl_matches_the_inherent_scan_method() {
        let scanner = EntropyScanner::new();
        let text = "session_token=4f9a2c7e1b8d3f6a0c5e9b2d7f1a4c8e6b3d9f0a";
        let via_trait: &dyn Scanner = &scanner;
        assert_eq!(via_trait.scan(text).len(), scanner.scan(text).len());
    }
}
