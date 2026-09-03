use regex::Regex;
use safeprompt_common::{Finding, FindingCategory, Scanner};

mod entropy;
pub use entropy::EntropyScanner;

/// Ports the "credentials" category of `backend/detection/layer1_regex.py`
/// plus Presidio's regex-only `CryptoRecognizer` pattern (`backend/venv/.../
/// presidio_analyzer/predefined_recognizers/generic/crypto_recognizer.py`) —
/// crypto addresses are flagged here, not `crates/pii`, matching the Python
/// engine's `CRYPTO -> "credentials"` category mapping in `layer2_presidio.py`.
/// **Known gap, carried over intentionally:** unlike credit-card/IBAN/ABA in
/// `crates/pii`, this does not run the Bitcoin Base58Check/Bech32 checksum —
/// that's real, non-trivial crypto code Presidio itself only uses to *raise*
/// confidence, not to gate detection, so a regex-only match is genuine parity,
/// not a regression.
pub struct SecretScanner {
    aws_key_regex: Regex,
    aws_secret_key_context_regex: Regex,
    aws_session_token_context_regex: Regex,
    openai_key_regex: Regex,
    anthropic_key_regex: Regex,
    gcp_key_regex: Regex,
    azure_secret_regex: Regex,
    password_context_regex: Regex,
    db_connection_regex: Regex,
    jwt_regex: Regex,
    private_key_regex: Regex,
    crypto_wallet_regex: Regex,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretScanner {
    pub fn new() -> Self {
        Self {
            // Real gap, live-caught 2026-08-08: only AKIA (long-term IAM
            // user access keys) was matched -- ASIA (temporary/STS access
            // keys, e.g. from an assumed role or `sts get-session-token`)
            // was never covered at all despite being an equally real,
            // equally sensitive AWS credential prefix. Both are 20 chars
            // total (4-char prefix + 16 alphanumeric); which prefix
            // actually matched is captured at push time below to keep the
            // temporary/long-term distinction visible in `match_name`
            // rather than collapsing both into one generic label.
            aws_key_regex: Regex::new(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b").unwrap(),
            // Context-gated, same posture as `password_context_regex`/
            // `azure_secret_regex` right below (this file's own existing
            // "field name + value" convention, not a new detection
            // paradigm) -- an AWS secret access key or session token has
            // no fixed structural pattern of its own the way an access key
            // ID does (both are just high-entropy blobs Presidio/this
            // crate can't tell apart from any other random string without
            // the field name that names them). `(?i)` covers both the ini-
            // style `aws_secret_access_key = ...` and env-var-style
            // `AWS_SECRET_ACCESS_KEY=...` shapes in one pattern.
            aws_secret_key_context_regex: Regex::new(r"(?i)\baws_secret_access_key\s*[:=]\s*\S+").unwrap(),
            aws_session_token_context_regex: Regex::new(r"(?i)\baws_session_token\s*[:=]\s*\S+").unwrap(),
            openai_key_regex: Regex::new(r"\b(sk-[a-zA-Z0-9]{32,})\b").unwrap(),
            anthropic_key_regex: Regex::new(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b").unwrap(),
            gcp_key_regex: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
            azure_secret_regex: Regex::new(
                r"(?i)\b(?:azure|azuread|x-api-key|api_key|secret|client_secret)=\S+\b",
            )
            .unwrap(),
            password_context_regex: Regex::new(
                r"(?i)\b(?:password|passwd|pwd|secret)\s*(?:is|[=:])\s*\S+\b",
            )
            .unwrap(),
            db_connection_regex: Regex::new(r"\b(?:mongodb|postgres|mysql|redis)://\S+\b").unwrap(),
            jwt_regex: Regex::new(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b").unwrap(),
            private_key_regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----").unwrap(),
            // Tightened 2026-08-05: the previous char class `[a-zA-HJ-NP-Z0-9]`
            // allowed digit '0' and lowercase 'l' -- real base58 (what
            // legacy/P2SH Bitcoin addresses actually use) excludes both,
            // specifically to avoid visual ambiguity with 'O'/'1'/'I'. That
            // gap meant any lowercase hex string starting with '1' or '3'
            // (a git-style commit/app-version hash, for one) matched --
            // live-caught 2026-08-05 flooding the browser extension with
            // false blocks on an AI site's own telemetry, which is full of
            // exactly that shape of ID. Bech32 (bc1...) addresses get their
            // own branch: lowercase-only per BIP173, tighter length bound.
            crypto_wallet_regex: Regex::new(r"\b(?:bc1[a-z0-9]{38,58}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").unwrap(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in self.aws_key_regex.find_iter(text) {
            let match_name = if mat.as_str().starts_with("ASIA") {
                "AWS_ACCESS_KEY_TEMPORARY"
            } else {
                "AWS_ACCESS_KEY"
            };
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: match_name.to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_AWS_KEY]".to_string()),
            });
        }

        for mat in self.aws_secret_key_context_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "AWS_SECRET_ACCESS_KEY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_AWS_SECRET]".to_string()),
            });
        }

        for mat in self.aws_session_token_context_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "AWS_SESSION_TOKEN".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_AWS_SESSION_TOKEN]".to_string()),
            });
        }

        for mat in self.openai_key_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "OPENAI_API_KEY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_API_KEY]".to_string()),
            });
        }

        for mat in self.jwt_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "JWT_BEARER_TOKEN".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_JWT]".to_string()),
            });
        }

        for mat in self.private_key_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "PRIVATE_RSA_KEY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_PRIVATE_KEY]".to_string()),
            });
        }

        for mat in self.anthropic_key_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "ANTHROPIC_API_KEY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_API_KEY]".to_string()),
            });
        }

        for mat in self.gcp_key_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "GCP_API_KEY".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_API_KEY]".to_string()),
            });
        }

        for mat in self.azure_secret_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "AZURE_SECRET".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_SECRET]".to_string()),
            });
        }

        for mat in self.password_context_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "PASSWORD_CONTEXT".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_PASSWORD]".to_string()),
            });
        }

        for mat in self.db_connection_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "DB_CONNECTION_STRING".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "CRITICAL".to_string(),
                redacted_replacement: Some("[REDACTED_DB_CONNECTION]".to_string()),
            });
        }

        for mat in self.crypto_wallet_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Secret,
                match_name: "CRYPTO_WALLET".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_WALLET]".to_string()),
            });
        }

        findings
    }
}

impl Scanner for SecretScanner {
    fn scan(&self, text: &str) -> Vec<Finding> {
        SecretScanner::scan(self, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let scanner = SecretScanner::new();
        let input = "My AWS key is AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "AWS_ACCESS_KEY");
    }

    #[test]
    fn test_temporary_sts_access_key_is_detected_distinctly_from_long_term() {
        let scanner = SecretScanner::new();
        let findings = scanner.scan("Sample Session Key ID: ASIAIOSFODNN7EXAMPLE (Temporary keys use the ASIA prefix)");
        let f = findings.iter().find(|f| f.snippet == "ASIAIOSFODNN7EXAMPLE").expect("expected the ASIA-prefixed key to be detected");
        assert_eq!(f.match_name, "AWS_ACCESS_KEY_TEMPORARY", "an ASIA-prefixed key must be distinguished from a long-term AKIA one");
        assert_eq!(f.severity, "CRITICAL");

        // Regression: the pre-existing AKIA case must still classify as
        // the long-term variant, unchanged.
        let akia_findings = scanner.scan("Sample Access Key ID: AKIAIOSFODNN7EXAMPLE");
        assert!(akia_findings.iter().any(|f| f.match_name == "AWS_ACCESS_KEY" && f.snippet == "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_aws_secret_key_and_session_token_config_context_detected() {
        let scanner = SecretScanner::new();
        // Exact shape from a real ~/.aws/credentials-style config block.
        let text = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_session_token = FwoGZXIvYXdzEAf//////////wEaDMvS39n08sS85u0b";
        let findings = scanner.scan(text);

        assert!(findings.iter().any(|f| f.match_name == "AWS_ACCESS_KEY" && f.snippet == "AKIAIOSFODNN7EXAMPLE"));
        let secret = findings.iter().find(|f| f.match_name == "AWS_SECRET_ACCESS_KEY").expect("expected aws_secret_access_key context to be flagged");
        assert!(secret.snippet.contains("wJalrXUtnFEMI"), "the whole field=value pair should be the match, got {:?}", secret.snippet);
        assert_eq!(secret.severity, "CRITICAL");

        let token = findings.iter().find(|f| f.match_name == "AWS_SESSION_TOKEN").expect("expected aws_session_token context to be flagged");
        assert!(token.snippet.contains("FwoGZXIvYXdzEAf"));
        assert_eq!(token.severity, "CRITICAL");
    }

    #[test]
    fn test_aws_env_var_style_field_names_also_detected_case_insensitively() {
        let scanner = SecretScanner::new();
        let findings = scanner.scan("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(findings.iter().any(|f| f.match_name == "AWS_SECRET_ACCESS_KEY"), "env-var-style AWS_SECRET_ACCESS_KEY=... must also be detected, got {findings:?}");
    }

    #[test]
    fn test_anthropic_and_gcp_key_detection() {
        let scanner = SecretScanner::new();
        let input = "keys: sk-ant-api03-abcdefghijklmnopqrstuvwx and AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
        let findings = scanner.scan(input);
        assert!(findings.iter().any(|f| f.match_name == "ANTHROPIC_API_KEY"));
        assert!(findings.iter().any(|f| f.match_name == "GCP_API_KEY"));
    }

    #[test]
    fn test_db_connection_string_detection() {
        let scanner = SecretScanner::new();
        let findings = scanner.scan("conn: postgres://user:pass@db.example.com:5432/prod");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "DB_CONNECTION_STRING");
    }

    #[test]
    fn test_crypto_wallet_detection() {
        let scanner = SecretScanner::new();
        let findings = scanner.scan("send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please");
        assert!(findings.iter().any(|f| f.match_name == "CRYPTO_WALLET"));
    }

    #[test]
    fn test_hex_hash_is_not_a_crypto_wallet() {
        // Regression for a real false positive, live-caught 2026-08-05: an
        // AI site's own client app_version (a git-style commit hash) tested
        // positive under the old char class, which allowed digit '0' and
        // lowercase 'l' -- neither of which real base58 permits. Flooded
        // the browser extension with false blocks on the site's own
        // telemetry, not anything a user typed.
        let scanner = SecretScanner::new();
        let findings = scanner.scan("app_version 1827e06d85a24a9606e4199fake40charhash00");
        assert!(!findings.iter().any(|f| f.match_name == "CRYPTO_WALLET"), "a lowercase hex hash must not be flagged as a crypto wallet address");
    }
}
