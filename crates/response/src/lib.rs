use safeprompt_common::Finding;
use safeprompt_pii::PiiScanner;
use safeprompt_secrets::SecretScanner;

pub struct ResponseFilter {
    pii_scanner: PiiScanner,
    secret_scanner: SecretScanner,
}

impl Default for ResponseFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseFilter {
    pub fn new() -> Self {
        Self {
            pii_scanner: PiiScanner::new(),
            secret_scanner: SecretScanner::new(),
        }
    }

    /// Scan only -- deliberately does NOT redact itself. Redaction now
    /// happens centrally in `safeprompt_inspector::Inspector::
    /// inspect_response`, which collects findings from every scanner
    /// (this one, NER, entropy, custom-keyword) before applying a single
    /// JSON-aware redaction pass (`safeprompt_common::apply_redactions`)
    /// -- see that function's own doc comment for the real bug this
    /// split fixes: four separate naive whole-text `.replace()` calls
    /// (this one used to be the first of them) can each corrupt a JSON
    /// response body's syntax independently, and even a single JSON-aware
    /// pass needs every finding up front to redact all of them in one
    /// walk of the parsed structure.
    pub fn scan_response(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(self.secret_scanner.scan(text));
        findings.extend(self.pii_scanner.scan(text));
        findings
    }
}
