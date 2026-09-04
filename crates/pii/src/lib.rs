use regex::Regex;
use safeprompt_common::{Finding, FindingCategory, Scanner};

/// Ports `backend/detection/layer1_regex.py`'s pii/financial/internal patterns
/// plus the checksum-validated recognizers Presidio's `predefined_recognizers`
/// use for CREDIT_CARD/IBAN_CODE/ABA_ROUTING_NUMBER (`backend/venv/.../presidio_analyzer/
/// predefined_recognizers/{generic,country_specific}/*.py`) — a regex match alone isn't
/// enough for these three, so each carries its own checksum validator below,
/// same as Presidio's `validate_result`.
pub struct PiiScanner {
    email_regex: Regex,
    phone_regex: Regex,
    pan_regex: Regex,
    aadhaar_regex: Regex,
    ssn_regex: Regex,
    credit_card_regex: Regex,
    iban_regex: Regex,
    aba_routing_regex: Regex,
    internal_url_regex: Regex,
    passport_patterns: Vec<PassportPattern>,
    mrz_regex: Regex,
    gstin_regex: Regex,
    dob_patterns: Vec<Regex>,
    ein_regex: Regex,
    driver_license_patterns: Vec<Regex>,
    mbi_dashed_regex: Regex,
    mbi_nodash_regex: Regex,
    street_address_regex: Regex,
}

/// One entry in the passport pattern registry -- deliberately a registry of
/// small country-specific patterns rather than one "universal" regex, since
/// passport number formats aren't standardized across countries the way
/// PAN/Aadhaar/SSN are within one. Every pattern here is sourced from a real
/// Presidio `PatternRecognizer` (`backend/venv/.../predefined_recognizers/
/// country_specific/{india,us,uk,korea}/*.py`), not guessed -- and every one
/// of those upstream patterns is itself scored "weak"/"very weak" (0.01-0.1
/// confidence) by Presidio's own authors, because a short letter+digit
/// combination collides with order IDs/ticket numbers/tracking codes without
/// more context. That's exactly why `context_required` exists below.
struct PassportPattern {
    match_name: &'static str,
    regex: Regex,
    /// Patterns weak enough that Presidio itself only trusts them with a
    /// context word nearby (its own CONTEXT list mechanism) are gated the
    /// same way here: they produce no finding at all without a passport
    /// keyword in the surrounding text, rather than flooding on every
    /// matching digit run (the same class of bug the phone-number regex's
    /// own doc comment above describes and fixes). India's original pattern
    /// is the one exception -- kept unconditional (context only upgrades its
    /// severity, doesn't gate it) to preserve the exact behavior this crate
    /// already shipped and tested before this registry existed.
    context_required: bool,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    pub fn new() -> Self {
        Self {
            email_regex: Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap(),
            // The two separators between the 3-3-4 digit groups are
            // deliberately REQUIRED (not `[-.\s]?`), unlike an earlier
            // version of this regex -- live-caught 2026-08-05: with them
            // optional, this matched *any* bare 10-digit run anywhere in a
            // JSON blob (a timestamp fragment, a client_thread_id, a
            // counter value), which flooded the browser extension with
            // false PHONE_NUMBER blocks on an AI site's own telemetry
            // calls, not anything a user typed. Requiring a real separator
            // (space/dash/dot) between groups is a deliberate precision-
            // over-recall tradeoff: a phone number typed with literally no
            // visual separator at all (a bare 10-digit blob) no longer
            // matches, but that's also indistinguishable from an arbitrary
            // numeric ID without more context this regex-only layer
            // doesn't have -- and the false-positive cost of matching every
            // 10-digit number on the internet was far worse in practice.
            // The optional country-code prefix group is unchanged.
            phone_regex: Regex::new(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b").unwrap(),
            pan_regex: Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b").unwrap(),
            // The trailing `(?:\s\d{4})*` (mandatory space before each
            // extra group) fixes a real leak, live-caught 2026-08-06: the
            // original pattern matched exactly 3 groups (12 digits) and
            // stopped, so a 4th space-separated digit group immediately
            // after a real Aadhaar match (e.g. someone pasting
            // "7614 3156 5477 4567") fell entirely outside the match and
            // was sent in plain text right next to the redaction
            // placeholder -- worse than not detecting it, since it looked
            // "handled." An earlier attempt at this fix widened the
            // repetition to `(?:\s?\d{4}){2,}` (space *optional* on every
            // group, unbounded) -- that over-corrected and started
            // matching 16-digit continuous credit-card numbers too
            // (4+4*3=16 is just as valid a decomposition as 4+4*2=12 once
            // the count is unbounded and spaces aren't required), caught
            // by this crate's own pre-existing credit-card tests. Requiring
            // a real space before any group *beyond* the first three
            // targets the actual observed bug (adjacent groups a human
            // visually separated the same way) without changing how a
            // continuous digit run is matched at all -- a continuous
            // 12-digit Aadhaar still matches (unchanged from before), a
            // continuous 16-digit card still doesn't (unchanged from
            // before), and a same-length-but-wrong-shape digit run (e.g.
            // 15 continuous digits) still correctly matches nothing, since
            // `\b` still refuses to land mid-run.
            aadhaar_regex: Regex::new(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}(?:\s\d{4})*\b").unwrap(),
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            // Real gap, live-caught 2026-08-08 testing an actual sample
            // document through a real running Agent: this used to require
            // one continuous digit run with zero separators, so a card
            // number written the way every real card/checkout form/invoice
            // actually displays one -- grouped with spaces or dashes, e.g.
            // "5105 1051 0510 5105" -- matched nothing at all here.
            // (Worse, that exact Mastercard test number then got scooped up
            // and mislabeled by the Aadhaar regex instead, since its first
            // 12 digits happen to pass the Verhoeff checksum by chance --
            // see `aadhaar_checksum_valid`'s doc comment for the other half
            // of that same finding.) `[ -]?` between each 4-digit group
            // (6-digit/5-digit for Amex's 4-6-5 convention) now accepts a
            // space, a dash, or nothing, matching every grouping real cards
            // use while a fully continuous 16-digit run still matches
            // exactly as before. `luhn_checksum_valid` strips separators
            // before validating either way, so this can't start accepting
            // non-card digit runs just because grouping got looser.
            credit_card_regex: Regex::new(
                r"\b(?:4[0-9]{3}(?:[ -]?[0-9]{4}){3}|4[0-9]{12}|5[1-5][0-9]{2}(?:[ -]?[0-9]{4}){3}|3[47][0-9]{2}(?:[ -]?[0-9]{6})(?:[ -]?[0-9]{5})|6(?:011|5[0-9]{2})(?:[ -]?[0-9]{4}){3})\b",
            )
            .unwrap(),
            iban_regex: Regex::new(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b").unwrap(),
            aba_routing_regex: Regex::new(r"\b[0123678]\d{8}\b").unwrap(),
            internal_url_regex: Regex::new(
                r"(?i)\b(?:https?://)?(?:[\w-]+\.)?(?:internal|corp|company)\.[a-z]{2,}\b",
            )
            .unwrap(),
            // Country-specific passport registry -- see `PassportPattern`'s
            // own doc comment above for why this is several small patterns
            // instead of one generic regex. Every regex below is copied
            // byte-for-byte (adjusted only where the `regex` crate can't
            // express something Presidio's `re` used, noted per-entry) from
            // the real vendored Presidio recognizer, not invented.
            passport_patterns: vec![
                // India: 1 letter + 7 digits (`in_passport_recognizer.py`).
                // Unconditional/context-optional (see `context_required`'s
                // doc comment) -- this is the one already shipped before
                // the registry existed; behavior preserved exactly.
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_IN",
                    regex: Regex::new(r"\b[A-Z][1-9]\d\s?\d{4}[1-9]\b").unwrap(),
                    context_required: false,
                },
                // US "next generation" format: 1 letter + 8 digits
                // (`us_passport_recognizer.py`'s "Passport Next Generation
                // (very weak)", 0.1 confidence upstream).
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_US",
                    regex: Regex::new(r"\b[A-Z][0-9]{8}\b").unwrap(),
                    context_required: true,
                },
                // US older format: a bare 9-digit number
                // (`us_passport_recognizer.py`'s "Passport (very weak)",
                // 0.05 confidence -- the single weakest pattern in any of
                // the vendored recognizers checked for this registry).
                // Structurally identical to the bare-digit-run false
                // positives already fixed for phone numbers/Aadhaar above,
                // so this one is *never* flagged without a context keyword,
                // no exceptions.
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_US",
                    regex: Regex::new(r"\b[0-9]{9}\b").unwrap(),
                    context_required: true,
                },
                // UK (2015+): 2 letters + 7 digits
                // (`uk_passport_recognizer.py`, 0.1 confidence upstream).
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_GB",
                    regex: Regex::new(r"\b[A-Z]{2}\d{7}\b").unwrap(),
                    context_required: true,
                },
                // South Korea, current format: one of M/S/R/O/D + 3 digits +
                // 1 letter + 4 digits (`kr_passport_recognizer.py`, 0.1
                // confidence upstream). Presidio's own pattern uses a
                // negative lookbehind/lookahead (`(?<!...)`/`(?!...)`) to
                // stop this from matching mid-run inside a longer
                // alphanumeric string -- the `regex` crate (unlike Python's
                // `re`) has no lookaround support at all, so `\b` word
                // boundaries substitute here; in practice that achieves
                // nearly the same effect (no adjacent word character on
                // either side of the match), just not byte-for-byte
                // identical to the upstream pattern the way India/US/UK's
                // patterns above are.
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_KR",
                    regex: Regex::new(r"\b[MSRODmsrod]\d{3}[A-Za-z]\d{4}\b").unwrap(),
                    context_required: true,
                },
                // South Korea, previous format: M/S/R/O/D + 8 digits
                // (`kr_passport_recognizer.py`, 0.05 confidence upstream --
                // same lookaround-to-`\b` substitution as above).
                PassportPattern {
                    match_name: "PASSPORT_NUMBER_KR",
                    regex: Regex::new(r"\b[MSRODmsrod]\d{8}\b").unwrap(),
                    context_required: true,
                },
            ],
            // MRZ (Machine Readable Zone), TD3/passport format: two 44-char
            // lines. Line 1 is the name/issuing-country line; line 2 packs
            // the passport number, nationality, DOB, sex, and expiry, each
            // followed by its own ICAO 7-3-1 weighted check digit (see
            // `mrz_check_digit` below) -- a real, country-independent
            // structural signal that doesn't depend on knowing any one
            // country's passport-number shape at all, unlike every pattern
            // above. `(?m)` so `^`/`$` anchor to each line rather than the
            // whole (possibly multi-line) scanned text.
            //
            // 2026-09-04: line 1's trailing name-padding run was originally
            // pinned to an EXACT 39 characters (5 fixed chars + 39 = 44).
            // A real-machine sample sweep against 10 genuine passport-photo
            // OCR outputs (`sample_directory_sweep`, safeprompt-local-api)
            // found this exact-length requirement was THE reason 3 of them
            // (Australia, South Africa, Finland) produced zero findings at
            // all -- real OCR reliably drops or adds 1-3 `<` characters
            // from a long run of identical fill characters (a well-known
            // OCR failure mode against repeated glyphs), so line 1 came
            // back 41-43 chars instead of 44. Line 2 -- the line that
            // actually carries the checksums -- was unaffected in every one
            // of those samples and validated correctly once line 1 stopped
            // rejecting the whole match outright. Widened to a tolerant
            // range (30-42) instead of an exact count: this does NOT weaken
            // the anti-false-positive posture at all, since line 2's
            // `mrz_line2_checksums_valid` check below (unchanged, still a
            // real ICAO checksum, not a shape match) is what actually gates
            // the finding -- this range only stops line 1's un-checksummed
            // decorative padding from vetoing a checksum-valid line 2.
            mrz_regex: Regex::new(
                r"(?m)^(P[A-Z<][A-Z]{3}[A-Z<]{30,42})\r?\n([A-Z0-9<]{9}[0-9][A-Z<]{3}[0-9]{6}[0-9][MFX<][0-9]{6}[0-9][A-Z0-9<]{14}[0-9<][0-9])$",
            )
            .unwrap(),
            // GSTIN (Indian GST registration number): 2-digit state code +
            // 10-char PAN (5 letters + 4 digits + 1 check letter) + 1
            // alphanumeric entity number + literal 'Z' + 1 alphanumeric
            // checksum character = 15 characters total. Unlike passport,
            // this DOES have a real checksum ("Luhn mod 36", see
            // `gstin_checksum_valid` below) -- validated the same way
            // CREDIT_CARD/IBAN_CODE/ABA_ROUTING_NUMBER are, so it's a
            // Financial finding, not just a pattern match.
            gstin_regex: Regex::new(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b").unwrap(),
            // Date of birth -- a real, live-caught gap (2026-08-08, found
            // testing OCR against a real passport image: name/DOB/place-of-
            // birth were extracted and shown in plain text alongside a
            // correctly-redacted document number, since nothing in this
            // scanner recognized a bare date as PII at all). Deliberately
            // NOT unconditional like most patterns above -- a date alone
            // ("07 JUN 1984") is indistinguishable from any other date
            // (an issue date, an expiry date, a meeting time, a historical
            // reference) without context, so EVERY entry here is
            // context-gated via `has_context_keyword`/`DOB_CONTEXT_KEYWORDS`
            // below, no exceptions -- same "weak pattern needs context"
            // posture as the passport registry's `context_required: true`
            // entries, not the unconditional India passport pattern.
            // Three shapes covering common government-document/passport
            // date conventions: "07 JUN 1984" (day + 3-letter month, the
            // MRZ-adjacent printed convention this exact passport uses),
            // "07/06/1984" or "07-06-1984" (day/month/year, slash or
            // dash), and ISO "1984-06-07".
            dob_patterns: vec![
                Regex::new(r"(?i)\b\d{1,2}\s+[A-Z]{3}\s+\d{4}\b").unwrap(),
                Regex::new(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b").unwrap(),
                Regex::new(r"\b\d{4}-\d{2}-\d{2}\b").unwrap(),
            ],
            // SP-DLP-007: EIN (US Employer Identification Number), format
            // NN-NNNNNNN. No public checksum exists (IRS "campus code"
            // prefixes are a real but non-stable list this crate has no
            // authoritative offline source for -- hardcoding one risks
            // silent false negatives as IRS adds prefixes over time), so
            // this follows the same honest posture as the weak passport
            // patterns above: shape-only regex, always context-gated, never
            // an unconditional finding. No vendored Presidio recognizer for
            // this exists to port from (checked `predefined_recognizers/
            // country_specific/us/` -- bank/driver_license/itin/mbi/npi/
            // passport/ssn only, no EIN).
            ein_regex: Regex::new(r"\b\d{2}-\d{7}\b").unwrap(),
            // SP-DLP-007: US driver's license. Real-world formats vary by
            // state with no unifying structure (unlike SSN/PAN/Aadhaar), so
            // rather than port Presidio's own `UsLicenseRecognizer` verbatim
            // (a single 15-way alternation scored only 0.3 "weak" by its own
            // authors, and containing what looks like a typo --
            // `A-Z]{2}[0-9]{2,5}` -- inside the alternation itself), this
            // uses two representative shapes (letter-prefixed alphanumeric,
            // and a bare digit run) and -- like every weak pattern in this
            // file -- requires a nearby context keyword unconditionally, no
            // exceptions. A bare digit run is exactly the same false-positive
            // class already fixed for phone numbers/US passport above.
            driver_license_patterns: vec![
                Regex::new(r"\b[A-Z]{1,2}\d{5,12}\b").unwrap(),
                Regex::new(r"\b\d{7,9}\b").unwrap(),
            ],
            // SP-DLP-007: Medicare Beneficiary Identifier (MBI), CMS's
            // current 11-character format. Ported byte-for-byte from
            // Presidio's `UsMbiRecognizer` (`us_mbi_recognizer.py`) -- unlike
            // EIN/driver's-license above, this format's own character-class
            // restriction per position (positions 2/5/8/9 must be a letter
            // from a 20-letter alphabet that deliberately excludes
            // B/I/L/O/S/Z to avoid confusion with 0/1/5/2, positions 3/6 an
            // alphanumeric from that same restricted alphabet) is itself a
            // real structural signal, not just "11 alphanumeric characters" --
            // the same class of confidence MRZ's checksum or GSTIN's checksum
            // provide, just expressed as a charset constraint instead of
            // arithmetic. The dashed form (CMS's own printed convention,
            // XXXX-XXX-XXXX) is distinctive enough to fire unconditionally
            // (upgraded HIGH with context, same as India's passport pattern);
            // the no-dash form is closer to a plain alphanumeric run and stays
            // context-gated like every other weak pattern here.
            mbi_dashed_regex: Regex::new(
                r"\b[0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9]-[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9]-[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY][0-9][0-9]\b",
            )
            .unwrap(),
            mbi_nodash_regex: Regex::new(
                r"\b[0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY][0-9][0-9]\b",
            )
            .unwrap(),
            // SP-DLP-007: US street address. No checksum or vendored
            // Presidio pattern applies (Presidio's own `US_ADDRESS` support
            // is spaCy-NER-based, not regex -- this crate has no NER model
            // available at this layer, see `advanced_ner`'s separate,
            // heavier IPC-backed scanner). The house-number prefix plus a
            // required street-suffix keyword is the structural signal here
            // (same role MBI's charset restriction plays above) -- a bare
            // "123 Main" with no suffix word is deliberately NOT matched,
            // same precision-over-recall tradeoff already made for phone
            // numbers. Honest scope limit: US-only suffix vocabulary, no
            // apartment/unit-number or ZIP-code capture, no PO-box shape.
            // `\d{1,6}[A-Za-z]?` (not just `\d{1,6}`) so a unit letter glued
            // directly to the house number with no separating space (e.g.
            // "221B Baker St", a real, common US/UK convention) still
            // matches -- caught by this detector's own test fixture.
            street_address_regex: Regex::new(
                r"(?i)\b\d{1,6}[A-Za-z]?\s+(?:[A-Za-z]+\.?\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy)\.?\b",
            )
            .unwrap(),
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in self.email_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "EMAIL_ADDRESS".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "MEDIUM".to_string(),
                redacted_replacement: Some("[REDACTED_EMAIL]".to_string()),
            });
        }

        for mat in self.phone_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "PHONE_NUMBER".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "MEDIUM".to_string(),
                redacted_replacement: Some("[REDACTED_PHONE]".to_string()),
            });
        }

        for mat in self.pan_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "PAN_CARD".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_PAN]".to_string()),
            });
        }

        for mat in self.aadhaar_regex.find_iter(text) {
            if aadhaar_checksum_valid(mat.as_str()) {
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "AADHAAR_NUMBER".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_AADHAAR]".to_string()),
                });
            }
        }

        for mat in self.ssn_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "US_SSN".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "HIGH".to_string(),
                redacted_replacement: Some("[REDACTED_SSN]".to_string()),
            });
        }

        for mat in self.credit_card_regex.find_iter(text) {
            // The regex now allows " "/"-" separators between digit groups
            // (real cards are almost always written that way) -- strip them
            // before Luhn, which like every other checksum here operates on
            // the digit sequence only.
            let digits_only: String = mat.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
            if luhn_checksum_valid(&digits_only) {
                findings.push(Finding {
                    category: FindingCategory::Financial,
                    match_name: "CREDIT_CARD".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_CARD]".to_string()),
                });
            }
        }

        for mat in self.iban_regex.find_iter(text) {
            if iban_checksum_valid(mat.as_str()) {
                findings.push(Finding {
                    category: FindingCategory::Financial,
                    match_name: "IBAN_CODE".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_IBAN]".to_string()),
                });
            }
        }

        for mat in self.aba_routing_regex.find_iter(text) {
            if aba_checksum_valid(mat.as_str()) {
                findings.push(Finding {
                    category: FindingCategory::Financial,
                    match_name: "ABA_ROUTING_NUMBER".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "MEDIUM".to_string(),
                    redacted_replacement: Some("[REDACTED_ROUTING]".to_string()),
                });
            }
        }

        for mat in self.internal_url_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Internal,
                match_name: "INTERNAL_URL".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "LOW".to_string(),
                redacted_replacement: Some("[REDACTED_INTERNAL_URL]".to_string()),
            });
        }

        // Context detector: does a passport-related keyword appear near this
        // candidate match? Cheap, regex-free substring search over a small
        // window (not the whole text) around the match -- this is the
        // "My passport number is A1234567 should score higher confidence
        // than a bare A1234567" mechanism. Applied uniformly to every entry
        // in the registry: it gates the weak (`context_required: true`)
        // patterns outright (no finding at all without it) and upgrades the
        // unconditional India pattern from MEDIUM to HIGH when present.
        for pattern in &self.passport_patterns {
            for mat in pattern.regex.find_iter(text) {
                let has_context = has_context_keyword(text, mat.start(), mat.end(), PASSPORT_CONTEXT_KEYWORDS);
                if pattern.context_required && !has_context {
                    continue;
                }
                let severity = if has_context { "HIGH" } else { "MEDIUM" };
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: pattern.match_name.to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: severity.to_string(),
                    redacted_replacement: Some("[REDACTED_PASSPORT]".to_string()),
                });
            }
        }

        // MRZ: a genuinely country-independent, checksum-validated signal
        // (unlike every per-country pattern above). Masks the *entire*
        // two-line block, not just the extracted passport-number field --
        // the MRZ's other fields (DOB, nationality, sex, expiry) are
        // themselves personal data, so a policy that redacted only the
        // passport-number substring would still leak the rest verbatim.
        for cap in self.mrz_regex.captures_iter(text) {
            let full = cap.get(0).unwrap();
            let line2 = cap.get(2).unwrap().as_str();
            if mrz_line2_checksums_valid(line2) {
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "PASSPORT_MRZ".to_string(),
                    snippet: full.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_MRZ]".to_string()),
                });
            }
        }

        for mat in self.gstin_regex.find_iter(text) {
            if gstin_checksum_valid(mat.as_str()) {
                findings.push(Finding {
                    category: FindingCategory::Financial,
                    match_name: "GSTIN".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_GSTIN]".to_string()),
                });
            }
        }

        // Date of birth -- every pattern here is context-gated (see
        // dob_patterns's own doc comment); a bare date with no nearby
        // "date of birth"/"dob"/etc. keyword is never flagged at all, same
        // posture as the passport registry's weak, context_required
        // entries. Dedupes by match span rather than pushing once per
        // pattern: the three date shapes are mutually exclusive by
        // construction (a given substring can only look like one of
        // "DD MON YYYY"/"DD/MM/YYYY"/"YYYY-MM-DD" at once), but a
        // multi-pattern loop over the same text could still double-count
        // if that ever changed, so guard it explicitly rather than rely on
        // that invariant silently holding.
        let mut dob_matches_seen: Vec<(usize, usize)> = Vec::new();
        for pattern in &self.dob_patterns {
            for mat in pattern.find_iter(text) {
                let span = (mat.start(), mat.end());
                if dob_matches_seen.contains(&span) {
                    continue;
                }
                if !has_context_keyword(text, mat.start(), mat.end(), DOB_CONTEXT_KEYWORDS) {
                    continue;
                }
                dob_matches_seen.push(span);
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "DATE_OF_BIRTH".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_DOB]".to_string()),
                });
            }
        }

        // SP-DLP-007: EIN -- always context-gated, see field doc comment.
        for mat in self.ein_regex.find_iter(text) {
            if has_context_keyword(text, mat.start(), mat.end(), EIN_CONTEXT_KEYWORDS) {
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "US_EIN".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_EIN]".to_string()),
                });
            }
        }

        // SP-DLP-007: US driver's license -- always context-gated (both
        // shapes are weak on their own, see field doc comment). Dedupes by
        // span the same way `dob_patterns` does above, since a token like
        // "M1234567" can match both the letter-prefixed and (if the letter
        // were absent) overlapping shapes -- kept defensive even though
        // today's two patterns don't actually overlap in what they accept.
        let mut driver_license_seen: Vec<(usize, usize)> = Vec::new();
        for pattern in &self.driver_license_patterns {
            for mat in pattern.find_iter(text) {
                let span = (mat.start(), mat.end());
                if driver_license_seen.contains(&span) {
                    continue;
                }
                if !has_context_keyword(text, mat.start(), mat.end(), DRIVER_LICENSE_CONTEXT_KEYWORDS) {
                    continue;
                }
                driver_license_seen.push(span);
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "US_DRIVER_LICENSE".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_DRIVER_LICENSE]".to_string()),
                });
            }
        }

        // SP-DLP-007: Medicare Beneficiary Identifier -- dashed form is
        // unconditional (upgraded HIGH with context), no-dash form is
        // always context-gated. See `mbi_dashed_regex`'s field doc comment
        // for why the two are treated differently.
        for mat in self.mbi_dashed_regex.find_iter(text) {
            let has_context = has_context_keyword(text, mat.start(), mat.end(), MEDICARE_CONTEXT_KEYWORDS);
            let severity = if has_context { "HIGH" } else { "MEDIUM" };
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "MEDICARE_MBI".to_string(),
                snippet: mat.as_str().to_string(),
                severity: severity.to_string(),
                redacted_replacement: Some("[REDACTED_MEDICARE_ID]".to_string()),
            });
        }
        for mat in self.mbi_nodash_regex.find_iter(text) {
            if has_context_keyword(text, mat.start(), mat.end(), MEDICARE_CONTEXT_KEYWORDS) {
                findings.push(Finding {
                    category: FindingCategory::Pii,
                    match_name: "MEDICARE_MBI".to_string(),
                    snippet: mat.as_str().to_string(),
                    severity: "HIGH".to_string(),
                    redacted_replacement: Some("[REDACTED_MEDICARE_ID]".to_string()),
                });
            }
        }

        // SP-DLP-007: US street address -- the house-number + suffix
        // keyword shape is itself the structural signal, no extra context
        // gate needed (see field doc comment).
        for mat in self.street_address_regex.find_iter(text) {
            findings.push(Finding {
                category: FindingCategory::Pii,
                match_name: "US_STREET_ADDRESS".to_string(),
                snippet: mat.as_str().to_string(),
                severity: "MEDIUM".to_string(),
                redacted_replacement: Some("[REDACTED_ADDRESS]".to_string()),
            });
        }

        findings
    }
}

/// Trait impl is a thin delegate to the inherent `scan` above (kept, not
/// removed, since every existing call site — `Inspector` included — calls it
/// directly and Rust always resolves that to the inherent method first).
/// Lets `PiiScanner` be held as a `Box<dyn Scanner>` alongside
/// `safeprompt-scanner`'s IPC-backed Presidio scanner — see that trait's
/// doc comment in `safeprompt-common`.
impl Scanner for PiiScanner {
    fn scan(&self, text: &str) -> Vec<Finding> {
        PiiScanner::scan(self, text)
    }
}

/// Standard Luhn (mod-10) checksum — same algorithm as Presidio's
/// `CreditCardRecognizer.__luhn_checksum`. `digits` must be all-ASCII-digit
/// (guaranteed here since it comes straight out of `credit_card_regex`, which
/// has no separator characters).
fn luhn_checksum_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    for (i, c) in digits.chars().rev().enumerate() {
        let d = c.to_digit(10).unwrap();
        if i % 2 == 0 {
            sum += d;
        } else {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        }
    }
    sum % 10 == 0
}

/// Verhoeff checksum, the real algorithm UIDAI uses for an Aadhaar number's
/// 12th digit -- catches roughly 9 in 10 random 12-digit numbers that
/// previously matched the shape-only regex below with zero further
/// validation. Real bug, live-caught 2026-08-08 testing an actual sample
/// document through a real running Agent: a 12-digit US bank account number
/// ("Account Number: 987654321098") got flagged and redacted as
/// `AADHAAR_NUMBER` -- not a leak (it was still masked either way), but the
/// wrong category label on something that isn't a plausible Aadhaar at all,
/// the same class of gap `gstin_checksum_valid`/`luhn_checksum_valid`
/// already close for GSTIN/credit cards. Standard multiplication (`D`) and
/// permutation (`P`) tables, digits walked right-to-left; valid iff the
/// final running total is 0.
///
/// Validates only the *first* 12 digits, not "exactly 12 digits total": the
/// regex below deliberately matches a real Aadhaar's trailing adjacent
/// 4-digit groups too (anti-leak fix, 2026-08-06 -- see that regex's own
/// doc comment), so a genuine Aadhaar sitting next to another space-
/// separated digit group is a >12-digit match by design. Checksum-validating
/// only the leading 12 digits (the actual Aadhaar candidate) keeps that
/// anti-leak behavior intact instead of rejecting every such match outright.
fn aadhaar_checksum_valid(candidate: &str) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let digits: Vec<u8> = candidate.chars().filter_map(|c| c.to_digit(10)).map(|d| d as u8).collect();
    if digits.len() < 12 {
        return false;
    }
    let mut c: u8 = 0;
    for (i, &digit) in digits[..12].iter().rev().enumerate() {
        c = D[c as usize][P[i % 8][digit as usize] as usize];
    }
    c == 0
}

/// ISO 7064 MOD97-10 IBAN checksum: move the first 4 characters to the end,
/// convert letters to numbers (A=10..Z=35), and the resulting number mod 97
/// must equal 1. Mathematically equivalent to Presidio's `IbanRecognizer`
/// check-digit re-derivation, computed iteratively so no bignum type is needed.
fn iban_checksum_valid(candidate: &str) -> bool {
    let upper = candidate.to_uppercase();
    if upper.len() < 15 || upper.len() > 34 {
        return false;
    }
    let chars: Vec<char> = upper.chars().collect();
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return false;
    }
    let rearranged: String = upper[4..].chars().chain(upper[..4].chars()).collect();

    let mut remainder: u64 = 0;
    for c in rearranged.chars() {
        if let Some(d) = c.to_digit(10) {
            remainder = (remainder * 10 + d as u64) % 97;
        } else if c.is_ascii_alphabetic() {
            let value = c as u64 - 'A' as u64 + 10; // A=10 .. Z=35, always two digits
            remainder = (remainder * 10 + value / 10) % 97;
            remainder = (remainder * 10 + value % 10) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

/// ABA routing number checksum — same weighted-sum algorithm as Presidio's
/// `AbaRoutingRecognizer.__checksum`.
fn aba_checksum_valid(digits: &str) -> bool {
    const WEIGHTS: [u32; 9] = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = digits
        .chars()
        .zip(WEIGHTS.iter())
        .map(|(c, w)| c.to_digit(10).unwrap() * w)
        .sum();
    sum % 10 == 0
}

/// GSTIN check-digit validation ("Luhn mod 36" over the 36-character
/// alphabet `0-9A-Z`), the standard algorithm published by GSTN/widely
/// implemented by open-source GSTIN validators. Walks the first 14
/// characters right-to-left, alternating a x2/x1 multiplier starting at x2
/// for the character immediately left of the trailing check character
/// (mirrors how Luhn always doubles starting from the digit next to the
/// check digit) -- structurally the same "weighted digit-sum, add the
/// halves back together on overflow" shape as `luhn_checksum_valid` above,
/// just generalized from base-10 digits to base-36 alphanumerics.
fn gstin_checksum_valid(gstin: &str) -> bool {
    const CODE_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const MOD: u32 = 36; // CODE_CHARS.len(), the alphabet size
    if gstin.len() != 15 || !gstin.is_ascii() {
        return false;
    }
    let bytes = gstin.as_bytes();
    let mut factor: u32 = 2;
    let mut sum: u32 = 0;
    for i in (0..14).rev() {
        let code_point = match CODE_CHARS.iter().position(|&c| c == bytes[i]) {
            Some(p) => p as u32,
            None => return false,
        };
        let digit = factor * code_point;
        sum += (digit / MOD) + (digit % MOD);
        factor = if factor == 2 { 1 } else { 2 };
    }
    let check_code_point = (MOD - (sum % MOD)) % MOD;
    bytes[14] == CODE_CHARS[check_code_point as usize]
}

/// Passport-related keywords a nearby match boosts confidence on. Kept as
/// plain lowercase substrings (not a regex) so the window search below stays
/// a cheap `str::contains` scan, not a second regex engine invocation per
/// candidate match. English-only, matching this crate's existing scope
/// (same limit already documented for OCR's recognition model) -- non-English
/// context words (e.g. Presidio's Korean "여권" for its own KR recognizer)
/// aren't recognized here.
const PASSPORT_CONTEXT_KEYWORDS: &[&str] = &[
    "passport number",
    "passport no",
    "passport#",
    "passport #",
    "passport id",
    "travel document",
    "document number",
    // 2026-09-04: found via the real-OCR sample sweep -- an actual
    // Australian passport prints "DOCUMENT NO." (abbreviated, not
    // "document number"), so the visible passport-number field next to
    // it never matched any existing keyword. "document number" above is
    // kept too since it's still a real label some documents use in full.
    "document no",
    "passport details",
    "passport",
];

/// Date-of-birth keywords. Deliberately does NOT include "date of issue"/
/// "date of expiry"/"expiry"/"issued" -- those are dates too (this
/// passport's own layout prints all three within a few lines of each
/// other), but only date-of-birth is what this detector exists to catch;
/// keeping the keyword list specific to birth means the 40-char window
/// naturally binds to whichever label is actually closest to a given date,
/// not any date-shaped label on the page.
const DOB_CONTEXT_KEYWORDS: &[&str] = &[
    "date of birth",
    "d.o.b",
    "dob",
    "birth date",
    "born on",
    "born:",
];

/// EIN context keywords. "fein" (Federal EIN) and "tax id" both appear in
/// real IRS correspondence alongside the number itself.
const EIN_CONTEXT_KEYWORDS: &[&str] = &[
    "ein",
    "employer identification number",
    "federal tax id",
    "fein",
    "tax id number",
    "taxpayer id",
];

/// Driver's license context keywords, same list Presidio's own
/// `UsLicenseRecognizer.CONTEXT` uses.
const DRIVER_LICENSE_CONTEXT_KEYWORDS: &[&str] = &[
    "driver",
    "driving",
    "license",
    "licence",
    "permit",
    "lic#",
    "dl#",
    "dls",
];

/// Medicare/MBI context keywords, ported from Presidio's own
/// `UsMbiRecognizer.CONTEXT` -- "hic"/"hicn" cover the older Health
/// Insurance Claim Number this format replaced.
const MEDICARE_CONTEXT_KEYWORDS: &[&str] = &[
    "medicare",
    "mbi",
    "beneficiary",
    "cms",
    "medicaid",
    "hic",
    "hicn",
    "insurance id",
];

/// True if a context keyword from `keywords` appears within `WINDOW`
/// characters before or after the given match span. Deliberately checks
/// *both* sides (not just "before," as the motivating examples all show)
/// since natural phrasing puts the keyword after the value too ("A1234567
/// is my passport number"). Generalized from what was originally a
/// passport-only helper (`has_passport_context`) once a second category
/// (date of birth) needed the identical windowed-keyword-search logic.
fn has_context_keyword(text: &str, match_start: usize, match_end: usize, keywords: &[&str]) -> bool {
    const WINDOW: usize = 40;
    let window_start = floor_char_boundary(text, match_start.saturating_sub(WINDOW));
    let window_end = ceil_char_boundary(text, (match_end + WINDOW).min(text.len()));
    let window = text[window_start..window_end].to_lowercase();
    keywords.iter().any(|kw| window.contains(kw))
}

/// Walks an index down to the nearest valid UTF-8 char boundary at or before
/// it -- `text[a..b]` panics on a mid-character split, and an arbitrary
/// `match_start - WINDOW` byte offset has no guarantee of landing on one.
fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Same as `floor_char_boundary`, walking up instead of down.
fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

/// MRZ character value per ICAO 9303: digits are themselves, letters are
/// A=10..Z=35 (i.e. `10 + alphabet position`), and the `<` filler is 0.
fn mrz_char_value(c: char) -> Option<u32> {
    match c {
        '0'..='9' => c.to_digit(10),
        'A'..='Z' => Some(c as u32 - 'A' as u32 + 10),
        '<' => Some(0),
        _ => None,
    }
}

/// ICAO 9303 MRZ check digit: weighted sum over the field using repeating
/// weights 7, 3, 1, mod 10. The same algorithm computes the passport-number,
/// date-of-birth, and expiry-date check digits below -- only the input field
/// changes.
fn mrz_check_digit(field: &str) -> Option<u32> {
    const WEIGHTS: [u32; 3] = [7, 3, 1];
    let mut sum = 0u32;
    for (i, c) in field.chars().enumerate() {
        sum += mrz_char_value(c)? * WEIGHTS[i % 3];
    }
    Some(sum % 10)
}

/// Validates the three most semantically meaningful MRZ line-2 check digits
/// (passport number, date of birth, expiry date) against ICAO 9303. Honest
/// scope limit, not silently assumed covered: the personal-number field's
/// own check digit and the final composite check digit (computed over a
/// specific concatenation of several fields per the spec) are NOT validated
/// here -- getting the composite formula's exact field concatenation wrong
/// would be worse than not checking it, and the three checks below are
/// already real, checksum-level validation, not just a shape match, for the
/// two fields (passport number + dates) that actually matter for confidence.
/// `line2` must already be exactly 44 ASCII characters (guaranteed by
/// `mrz_regex`'s own capture group before this is ever called).
fn mrz_line2_checksums_valid(line2: &str) -> bool {
    let passport_number = &line2[0..9];
    let passport_check = line2[9..10].parse::<u32>().ok();
    let dob = &line2[13..19];
    let dob_check = line2[19..20].parse::<u32>().ok();
    let expiry = &line2[21..27];
    let expiry_check = line2[27..28].parse::<u32>().ok();

    mrz_check_digit(passport_number) == passport_check
        && mrz_check_digit(dob) == dob_check
        && mrz_check_digit(expiry) == expiry_check
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real, verbatim OCR output from `sample_directory_sweep`
    /// (safeprompt-local-api) against genuine sample passport images --
    /// the regression cases behind the 2026-09-04 MRZ line-1 length-range
    /// fix. Kept as a shared helper, not one string per test, since all
    /// three regression tests below scan the same three samples.
    fn real_ocr_passport_samples() -> [(&'static str, &'static str); 3] {
        [
            ("AusPassport", "FO\nAUSTRALIA\nPASSPORT\nDOCUMENT NO.\nSPECIMEN\nType / Tyse\nCode of issuing I Code ode IEat\nSatadn\nAUS\ndctr\nPA0940443\nP\nMerse/ Mom\nSPECIMEN\nCITIZEN\nJANE\nNatonalily I N\nAUSTRALIAN\nDutaoin iCada\nSM\n07 JUN 1984\nSeo I Sare\nPace of birty / Lles de reosone\nF\nCANBERRA\nDate of Ioue / Dale de SNiveese\nHolder's signetkure / Sigsatu dis sislsies\n01 MAR 2014\nDame of expiry 1 Dats chexparedi\ngane Citizen\n01 MAR 2024\nAulharty JAutonte\nAUSTRALIA\nP<AUSCITIZEN<<ANE<<<<<<<<<<<<<<<<<<<<<<<<<<\nPA09404433AUS8406077F1903212<17332717P<<<<68"),
            ("SouthAfrica", "Passport / Passeport\nPM \nREPUBLIC OF SOUTH AFRICA/REPUBLIQUE D'AFRIQUE DU CG\nZAF\nCanty sade/Clade dapaya\nMO0000001\nSPECIMEN\nJANE\nSOUTH AFRICAN\n / SUD-AFRICAINE\n01 JAN 1980\n8001014999082\nZAFSA\n12120\nF\nSou / Sen\nZAF\nPlec of t\n30 MAR 2009\nDEPT OF HOME AFFAIRS\n29 MAR 2019\nJ.Specimew\nPMZAFSPECMEN<<ANE<<<<<<<<<<<<<<<<<<<<<<<<\nM000000015ZAF8001014F19032908001014999082<30"),
            ("Finland", "t\nP..\nL9s1021:\n29272243\n1..\nPFALLUDAAORS\nSUOMI: FINLAND: FINLAND : FINLANDE\nP\nFIN\nXP1234567\nVirtanen\nMaria Olivia\nS\nSuoms Finland Finlan Finlande\n21.12.1971\nKO\n-426U\nn\nRovaniemi\nS\n22.08.2012\nMania Virtanen\nPolisen/Villmanstrand\nP<FINVIRTANEN<<MARIA<OLIVIA<<<<<<<<<<<<<<<<\nXP12345674FIN7112214F1708222211271<426U<<<08"),
        ]
    }

    #[test]
    fn test_mrz_detects_real_ocr_noisy_passports() {
        // 2026-09-04 regression test: before the line-1 length-range fix,
        // every one of these three real OCR outputs produced ZERO findings
        // -- not because line 2's checksum was wrong (it wasn't, on any of
        // the three), but because OCR reliably drops 1-3 `<` characters
        // from line 1's long fill-character run, and the old regex required
        // line 1 to be an exact 44 chars or the whole two-line match failed
        // outright. See mrz_regex's own doc comment for the full story.
        let scanner = PiiScanner::new();
        for (name, text) in real_ocr_passport_samples() {
            let findings = scanner.scan(text);
            assert!(
                findings.iter().any(|f| f.match_name == "PASSPORT_MRZ"),
                "{name}: expected a PASSPORT_MRZ finding on real noisy OCR output, got {findings:?}"
            );
        }
    }

    #[test]
    fn test_email_and_pan_detection() {
        let scanner = PiiScanner::new();
        let input = "Contact user@example.com with PAN ABCDE1234F";
        let findings = scanner.scan(input);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_ssn_detection() {
        let scanner = PiiScanner::new();
        let findings = scanner.scan("SSN on file: 078-05-1120");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "US_SSN");
    }

    #[test]
    fn test_valid_credit_card_passes_luhn() {
        let scanner = PiiScanner::new();
        // Well-known Luhn-valid Visa test number.
        let findings = scanner.scan("Card: 4111111111111111");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "CREDIT_CARD");
        assert_eq!(findings[0].category, FindingCategory::Financial);
    }

    #[test]
    fn test_invalid_credit_card_rejected_by_luhn() {
        let scanner = PiiScanner::new();
        // Right shape (16 digits, Visa prefix) but fails the Luhn checksum —
        // this is exactly the false-positive class checksum validation exists to cut.
        let findings = scanner.scan("Card: 4111111111111112");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_credit_card_detected_when_written_with_real_world_grouping() {
        // Real gap, live-caught 2026-08-08 via an actual sample document: a
        // continuous-digits-only regex matched nothing at all for a card
        // number written the way real cards/invoices/checkout forms
        // actually display one -- grouped with spaces or dashes, not one
        // 16-digit run. Space and dash grouping must both work. Uses the
        // well-known Luhn-valid Stripe/PayPal test numbers, not the sample
        // document's own placeholders ("4111-2222-3333-4444",
        // "5105 1051 0510 5105") -- those turned out to be made-up strings
        // that only *look* like cards and correctly fail Luhn, a property
        // of that fixture, not a detector bug (see
        // `test_mastercard_test_number_is_not_also_mislabeled_aadhaar` for
        // what a real Agent does with that exact fixture value instead).
        let scanner = PiiScanner::new();
        let spaced = scanner.scan("Mastercard: 5555 5555 5555 4444");
        assert!(spaced.iter().any(|f| f.match_name == "CREDIT_CARD"), "space-grouped card number must be detected, got {spaced:?}");

        let dashed = scanner.scan("Visa: 4111-1111-1111-1111");
        assert!(dashed.iter().any(|f| f.match_name == "CREDIT_CARD"), "dash-grouped card number must be detected, got {dashed:?}");

        let amex = scanner.scan("Amex: 3782 822463 10005");
        assert!(amex.iter().any(|f| f.match_name == "CREDIT_CARD"), "Amex's 4-6-5 grouping must be detected, got {amex:?}");
    }

    #[test]
    fn test_mastercard_test_number_is_not_also_mislabeled_aadhaar() {
        // The exact overlap this session's two fixes (Aadhaar checksum +
        // credit-card grouping) both touch: "5555 5555 5555 4444"'s leading
        // 12 digits happen to pass the Aadhaar Verhoeff checksum by pure
        // coincidence. It must be flagged as the credit card it actually
        // is, not (also, or instead) as an Aadhaar number.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Mastercard: 5555 5555 5555 4444");
        assert!(findings.iter().any(|f| f.match_name == "CREDIT_CARD"), "expected a CREDIT_CARD finding, got {findings:?}");
        assert!(!findings.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "a real card number must not also be flagged AADHAAR_NUMBER just because its prefix happens to pass Verhoeff, got {findings:?}");
    }

    #[test]
    fn test_a_card_shaped_but_luhn_invalid_number_may_still_coincidentally_match_aadhaar() {
        // Honest, documented limitation rather than a silently-passing gap:
        // the sample document that motivated this session's fixes used a
        // made-up "Mastercard" number ("5105 1051 0510 5105") that fails
        // Luhn (so it's correctly NOT flagged CREDIT_CARD) but whose leading
        // 12 digits pass the unrelated Aadhaar Verhoeff checksum by pure
        // coincidence -- so it still gets flagged, just under the wrong
        // category. Not a leak (still redacted either way) and not
        // realistically fixable without a much deeper cross-detector
        // overlap-resolution pass for a rare coincidence, so this test
        // exists to document the known behavior rather than assert
        // something false about it.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Mastercard: 5105 1051 0510 5105");
        assert!(!findings.iter().any(|f| f.match_name == "CREDIT_CARD"), "this fixture value is genuinely Luhn-invalid and must not be flagged as a card");
        assert!(findings.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "documents the known coincidental-checksum overlap rather than hiding it");
    }

    #[test]
    fn test_valid_iban_passes_checksum() {
        let scanner = PiiScanner::new();
        // Well-known IBAN checksum-validation example.
        let findings = scanner.scan("Please wire to GB82WEST12345698765432");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "IBAN_CODE");
    }

    #[test]
    fn test_invalid_iban_rejected_by_checksum() {
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Please wire to GB82WEST12345698765433");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_valid_aba_routing_passes_checksum() {
        let scanner = PiiScanner::new();
        // 021000021 is JPMorgan Chase NY's real, checksum-valid ABA routing number.
        let findings = scanner.scan("Routing number: 021000021");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_name, "ABA_ROUTING_NUMBER");
    }

    #[test]
    fn test_internal_url_detection() {
        let scanner = PiiScanner::new();
        let findings = scanner.scan("See https://wiki.internal.company.com for details");
        assert!(findings.iter().any(|f| f.match_name == "INTERNAL_URL"));
        assert!(findings.iter().any(|f| f.category == FindingCategory::Internal));
    }

    #[test]
    fn test_phone_number_still_detected_with_real_separators() {
        let scanner = PiiScanner::new();
        assert!(scanner.scan("call me at 555-123-4567").iter().any(|f| f.match_name == "PHONE_NUMBER"));
        assert!(scanner.scan("reach me on 555.123.4567").iter().any(|f| f.match_name == "PHONE_NUMBER"));
        assert!(scanner.scan("phone: (555) 123-4567").iter().any(|f| f.match_name == "PHONE_NUMBER"));
    }

    /// Builds a checksum-valid 12-digit Aadhaar number for a given
    /// 11-digit prefix by brute-forcing the one check digit that makes
    /// `aadhaar_checksum_valid` accept it -- same self-consistency
    /// principle as `valid_gstin_for`/`valid_mrz_for` below, rather than
    /// trusting a hand-picked 12-digit string to coincidentally be
    /// checksum-valid (real Aadhaar numbers are, on average, only 1 in 10
    /// random 12-digit strings that happen to be).
    fn valid_aadhaar_for(prefix11: &str) -> String {
        assert_eq!(prefix11.len(), 11);
        (0..=9)
            .map(|d| format!("{prefix11}{d}"))
            .find(|candidate| aadhaar_checksum_valid(candidate))
            .expect("aadhaar_checksum_valid must accept exactly one of the 10 possible check digits")
    }

    #[test]
    fn test_aadhaar_detected_spaced_and_continuous() {
        let scanner = PiiScanner::new();
        let aadhaar = valid_aadhaar_for("76143156547");
        let spaced_text = format!("my aadhaar number is {} {} {}", &aadhaar[0..4], &aadhaar[4..8], &aadhaar[8..12]);
        let spaced = scanner.scan(&spaced_text);
        assert!(spaced.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "spaced 4-4-4 checksum-valid Aadhaar must be detected, got {spaced:?}");
        let continuous = scanner.scan(&format!("my aadhaar number is {aadhaar}"));
        assert!(continuous.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "continuous (no-separator) checksum-valid Aadhaar must be detected too, got {continuous:?}");
    }

    #[test]
    fn test_aadhaar_does_not_leak_a_trailing_adjacent_digit_group() {
        // Real leak, live-caught 2026-08-06: the old regex matched exactly
        // 3 groups (12 digits) and stopped, so a 4th space-separated group
        // right after a real Aadhaar number fell outside the match and was
        // sent in plain text next to the redaction placeholder -- worse
        // than not detecting it at all, since it looked "handled." Checksum
        // validation (added 2026-08-08) only checks the leading 12 digits,
        // so this trailing-group behavior survives that change too -- see
        // `aadhaar_checksum_valid`'s own doc comment.
        let scanner = PiiScanner::new();
        let aadhaar = valid_aadhaar_for("76143156547");
        let text = format!("my aadhaar number is {} {} {} 4567", &aadhaar[0..4], &aadhaar[4..8], &aadhaar[8..12]);
        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1, "expected exactly one Aadhaar finding covering the whole digit run, got {findings:?}");
        assert_eq!(findings[0].match_name, "AADHAAR_NUMBER");
        assert_eq!(findings[0].snippet, format!("{} {} {} 4567", &aadhaar[0..4], &aadhaar[4..8], &aadhaar[8..12]), "the match must cover the trailing 4th group too, not just the first 12 digits");
    }

    #[test]
    fn test_a_checksum_invalid_12_digit_number_is_not_flagged_as_aadhaar() {
        // The actual bug this session's fix closes: a random 12-digit
        // number that merely *looks* like an Aadhaar (right shape, no
        // checksum) must not be mislabeled -- live-caught via a real bank
        // account number ("987654321098") getting flagged AADHAAR_NUMBER
        // and redacted under the wrong category.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Account Number: 987654321098");
        assert!(!findings.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "a checksum-invalid 12-digit number must not be flagged as an Aadhaar number, got {findings:?}");
    }

    #[test]
    fn test_aadhaar_does_not_collide_with_a_continuous_credit_card() {
        // Regression for an over-correction caught by this crate's own
        // pre-existing credit-card tests while fixing the trailing-group
        // leak above: an earlier, too-broad version of the Aadhaar regex
        // (unbounded `\s?` on every group) started matching whole 16-digit
        // continuous credit card numbers too, since 16 is just as valid a
        // multiple-of-4 decomposition as 12 once spaces aren't required.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Card: 4111111111111111");
        assert!(!findings.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "a continuous 16-digit credit card must not also be flagged as an Aadhaar number");
    }

    #[test]
    fn test_aadhaar_shaped_but_wrong_length_digit_run_is_not_flagged() {
        // 15 continuous digits (not a clean multiple of 4, i.e. not a real
        // Aadhaar shape) must not produce a spurious partial match --
        // there's no valid 12-digit *and* boundary-respecting window
        // inside a 15-digit run, so nothing should fire for this category.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("testing my aadhaar number 761431565477890");
        assert!(!findings.iter().any(|f| f.match_name == "AADHAAR_NUMBER"), "a 15-digit run isn't a valid Aadhaar shape and must not be flagged as one");
    }

    #[test]
    fn test_bare_ten_digit_run_is_not_a_phone_number() {
        // Regression for a real false positive, live-caught 2026-08-05: the
        // browser extension flooded false PHONE_NUMBER blocks on an AI
        // site's own telemetry, which is full of bare 10-digit IDs/
        // timestamp fragments/counters with no phone-like separators at
        // all. See this field's own doc comment for the precision/recall
        // tradeoff this fix makes.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("client_thread_id 4813494812");
        assert!(!findings.iter().any(|f| f.match_name == "PHONE_NUMBER"), "a bare unseparated 10-digit ID must not be flagged as a phone number");
        let findings2 = scanner.scan("\"value\":1785917881718");
        assert!(!findings2.iter().any(|f| f.match_name == "PHONE_NUMBER"), "a timestamp fragment must not be flagged as a phone number");
    }

    #[test]
    fn test_passport_number_pattern_detection() {
        let scanner = PiiScanner::new();
        // Same shape as Presidio's own IN_PASSPORT example pattern:
        // 1 letter + 7 digits (digit 1 and digit 8 both non-zero).
        let findings = scanner.scan("My passport number is M1234567");
        assert!(findings.iter().any(|f| f.match_name == "PASSPORT_NUMBER_IN"), "expected a passport-shaped token to be flagged, got {findings:?}");
        assert!(findings.iter().any(|f| f.category == FindingCategory::Pii));
    }

    #[test]
    fn test_passport_number_wrong_shape_not_flagged() {
        let scanner = PiiScanner::new();
        // Leading digit-group can't start or end with 0 per the pattern
        // (mirrors Presidio's own [1-9]...[1-9] boundary digits).
        let findings = scanner.scan("Order ID M0123450");
        assert!(!findings.iter().any(|f| f.match_name == "PASSPORT_NUMBER_IN"), "a shape with a leading/trailing zero digit must not match the passport pattern");
    }

    #[test]
    fn test_passport_context_upgrades_india_pattern_to_high_severity() {
        // The user's own motivating example: "My passport number is
        // A1234567" should score higher confidence than a bare "A1234567"
        // -- same finding either way (India's pattern is unconditional),
        // but severity differs on whether a context keyword is nearby.
        let scanner = PiiScanner::new();
        let with_context = scanner.scan("My passport number is M1234567");
        let f = with_context.iter().find(|f| f.match_name == "PASSPORT_NUMBER_IN").expect("expected a match");
        assert_eq!(f.severity, "HIGH", "a passport-shaped token near the word 'passport' should score HIGH, got {f:?}");

        let without_context = scanner.scan("Reference code: M1234567");
        let f2 = without_context.iter().find(|f| f.match_name == "PASSPORT_NUMBER_IN").expect("expected a match even without context -- India's pattern is unconditional");
        assert_eq!(f2.severity, "MEDIUM", "without a nearby passport keyword this should stay at the original MEDIUM severity, got {f2:?}");
    }

    #[test]
    fn test_weak_country_pattern_requires_context_to_fire_at_all() {
        // UK's pattern (2 letters + 7 digits) is registered
        // `context_required: true` -- unlike India's, it must produce NO
        // finding at all without a nearby passport keyword, since Presidio
        // itself only scores this shape 0.1 confidence.
        let scanner = PiiScanner::new();
        let bare = scanner.scan("Reference code: AB1234567");
        assert!(!bare.iter().any(|f| f.match_name == "PASSPORT_NUMBER_GB"), "a UK-passport-shaped token with no context must not be flagged at all, got {bare:?}");

        let with_context = scanner.scan("My UK passport number is AB1234567");
        assert!(with_context.iter().any(|f| f.match_name == "PASSPORT_NUMBER_GB" && f.severity == "HIGH"), "the same shape with a nearby passport keyword must be flagged HIGH, got {with_context:?}");
    }

    #[test]
    fn test_bare_nine_digit_run_never_flagged_as_us_passport_without_context() {
        // US's bare-9-digit pattern is the single weakest entry in the
        // registry (0.05 confidence upstream) -- same false-positive class
        // already fixed for phone numbers/timestamps above, so this must
        // never fire on an ordinary numeric ID even when "passport" appears
        // somewhere in the same text, as long as it's outside the (bounded,
        // not whole-text) context window.
        let scanner = PiiScanner::new();
        let filler = "x".repeat(60); // pushes "passport" well past the 40-char window on either side
        let text = format!("client_thread_id 481349481 {filler} I have a passport somewhere");
        let findings = scanner.scan(&text);
        assert!(!findings.iter().any(|f| f.match_name == "PASSPORT_NUMBER_US"), "a bare 9-digit ID must not be flagged when 'passport' is outside the context window, got {findings:?}");
    }

    /// Builds a checksum-valid MRZ (TD3, passport) two-line block for a
    /// given 9-character passport-number field, computing each check digit
    /// via the real `mrz_check_digit` function itself -- same
    /// self-consistency principle as `valid_gstin_for` below, rather than
    /// trusting a hand-copied "famous" ICAO example that could be
    /// misremembered digit-for-digit.
    fn valid_mrz_for(passport_number_field9: &str) -> String {
        assert_eq!(passport_number_field9.len(), 9);
        let dob = "800101"; // YYMMDD
        let expiry = "300101"; // YYMMDD
        let passport_check = mrz_check_digit(passport_number_field9).unwrap();
        let dob_check = mrz_check_digit(dob).unwrap();
        let expiry_check = mrz_check_digit(expiry).unwrap();
        let personal = "<".repeat(14);

        let line2 = format!(
            "{passport_number_field9}{passport_check}IND{dob}{dob_check}M{expiry}{expiry_check}{personal}<0"
        );
        assert_eq!(line2.len(), 44, "test-constructed line2 must be exactly 44 chars: {line2}");

        let mut name_field = "DOE<<JOHN".to_string();
        while name_field.len() < 39 {
            name_field.push('<');
        }
        let line1 = format!("P<IND{name_field}");
        assert_eq!(line1.len(), 44, "test-constructed line1 must be exactly 44 chars: {line1}");

        format!("{line1}\n{line2}")
    }

    #[test]
    fn test_valid_mrz_detected_and_masks_the_whole_block() {
        let scanner = PiiScanner::new();
        let mrz = valid_mrz_for("X1234567<");
        let findings = scanner.scan(&format!("Here is my passport MRZ:\n{mrz}\nThanks"));
        let f = findings.iter().find(|f| f.match_name == "PASSPORT_MRZ").expect("expected a PASSPORT_MRZ finding");
        assert_eq!(f.severity, "HIGH");
        assert_eq!(f.snippet, mrz, "the whole two-line MRZ block must be the match, not just the passport-number field");
    }

    #[test]
    fn test_mrz_with_tampered_check_digit_is_not_flagged() {
        let scanner = PiiScanner::new();
        let mut mrz = valid_mrz_for("X1234567<");
        // Flip the passport-number check digit (line2, position 9) to
        // something guaranteed wrong.
        let bytes_len = mrz.len();
        let check_pos = bytes_len - 44 + 9; // start of line2 + field offset
        let wrong_digit = if &mrz[check_pos..check_pos + 1] == "0" { '1' } else { '0' };
        mrz.replace_range(check_pos..check_pos + 1, &wrong_digit.to_string());

        let findings = scanner.scan(&format!("Here is my passport MRZ:\n{mrz}\nThanks"));
        assert!(!findings.iter().any(|f| f.match_name == "PASSPORT_MRZ"), "an MRZ block with a tampered check digit must not be flagged, got {findings:?}");
    }

    /// Builds a checksum-valid GSTIN for a given 14-character prefix by
    /// brute-forcing the trailing check character against the real
    /// `gstin_checksum_valid` function itself -- guarantees the test string
    /// is genuinely valid per the algorithm under test, rather than trusting
    /// a hand-copied real-world GSTIN that could be mistyped or misremembered.
    fn valid_gstin_for(prefix14: &str) -> String {
        const CODE_CHARS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        CODE_CHARS
            .chars()
            .map(|c| format!("{prefix14}{c}"))
            .find(|candidate| gstin_checksum_valid(candidate))
            .expect("gstin_checksum_valid must accept exactly one of the 36 possible check characters")
    }

    #[test]
    fn test_valid_gstin_passes_checksum() {
        let scanner = PiiScanner::new();
        // 2-digit state code + 5-letter + 4-digit + 1-letter PAN + 1
        // alphanumeric entity number + literal 'Z', matching the regex shape.
        let gstin = valid_gstin_for("29AAAAA0000A1Z");
        let findings = scanner.scan(&format!("Our GSTIN is {gstin}"));
        assert!(findings.iter().any(|f| f.match_name == "GSTIN"), "expected the checksum-valid GSTIN to be flagged, got {findings:?}");
        assert!(findings.iter().any(|f| f.category == FindingCategory::Financial));
    }

    #[test]
    fn test_invalid_gstin_rejected_by_checksum() {
        let scanner = PiiScanner::new();
        let valid = valid_gstin_for("29AAAAA0000A1Z");
        let valid_check_char = valid.chars().last().unwrap();
        const CODE_CHARS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let wrong_char = CODE_CHARS.chars().find(|&c| c != valid_check_char).unwrap();
        let broken = format!("{}{wrong_char}", &valid[..14]);
        let findings = scanner.scan(&format!("Our GSTIN is {broken}"));
        assert!(!findings.iter().any(|f| f.match_name == "GSTIN"), "a GSTIN-shaped string with a wrong check digit must not be flagged");
    }

    #[test]
    fn test_date_of_birth_detected_with_context_in_all_three_shapes() {
        let scanner = PiiScanner::new();
        for text in [
            "Date of Birth: 07 JUN 1984",
            "DOB: 07/06/1984",
            "Date of birth 1984-06-07",
        ] {
            let findings = scanner.scan(text);
            assert!(findings.iter().any(|f| f.match_name == "DATE_OF_BIRTH"), "expected a DOB finding for {text:?}, got {findings:?}");
            assert!(findings.iter().any(|f| f.category == FindingCategory::Pii));
        }
    }

    #[test]
    fn test_bare_date_with_no_context_is_not_flagged_as_dob() {
        // The whole reason this detector is context-gated at all: a date
        // alone is indistinguishable from any other date (a meeting, a
        // historical reference, a product release) without a nearby
        // "date of birth"-style keyword.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("The event is scheduled for 07 JUN 1984.");
        assert!(!findings.iter().any(|f| f.match_name == "DATE_OF_BIRTH"), "a bare date with no birth-related context must not be flagged, got {findings:?}");
    }

    #[test]
    fn test_issue_and_expiry_dates_are_not_mistaken_for_date_of_birth() {
        // Real-world regression shape, matching an actual specimen
        // passport's field layout (Document Type/Country/Surname/Given
        // Name/Nationality/Date of Birth/Sex/Place of Birth/Date of
        // Issue/Date of Expiry/Authority) -- only the birth date should be
        // flagged, and it must not pick up the wrong nearby label just
        // because two dates happen to appear on the same document.
        let scanner = PiiScanner::new();
        let text = "Document Type\nP\nCountry\nAUS\nSurname\nCITIZEN\nGiven Name\nJANE\nNationality\nAUSTRALIAN\n\
                     Date of Birth\n07 JUN 1984\nSex\nF\nPlace of Birth\nCANBERRA\n\
                     Date of issue\n01 MAR 2014\nDate of expiry\n01 MAR 2024\nAuthority\nAUSTRALIA";
        let findings = scanner.scan(text);
        let dob_findings: Vec<_> = findings.iter().filter(|f| f.match_name == "DATE_OF_BIRTH").collect();
        assert_eq!(dob_findings.len(), 1, "expected exactly the birth date to be flagged, not the issue/expiry dates too, got {findings:?}");
        assert_eq!(dob_findings[0].snippet, "07 JUN 1984");
    }

    // --- SP-DLP-007: missing PII detectors ---

    #[test]
    fn test_ein_requires_context_to_fire() {
        let scanner = PiiScanner::new();
        let bare = scanner.scan("Reference: 12-3456789");
        assert!(!bare.iter().any(|f| f.match_name == "US_EIN"), "an EIN-shaped number with no context must not be flagged, got {bare:?}");

        let with_context = scanner.scan("Our EIN is 12-3456789");
        assert!(with_context.iter().any(|f| f.match_name == "US_EIN"), "expected an EIN finding with context, got {with_context:?}");
        assert!(with_context.iter().any(|f| f.category == FindingCategory::Pii));
    }

    #[test]
    fn test_driver_license_requires_context_to_fire() {
        let scanner = PiiScanner::new();
        let bare = scanner.scan("Order number: A1234567");
        assert!(!bare.iter().any(|f| f.match_name == "US_DRIVER_LICENSE"), "a license-shaped token with no context must not be flagged, got {bare:?}");

        let with_context = scanner.scan("My driver's license number is A1234567");
        assert!(with_context.iter().any(|f| f.match_name == "US_DRIVER_LICENSE"), "expected a driver's license finding with context, got {with_context:?}");
    }

    #[test]
    fn test_bare_digit_driver_license_shape_requires_context() {
        let scanner = PiiScanner::new();
        let bare = scanner.scan("Tracking code 481349481");
        assert!(!bare.iter().any(|f| f.match_name == "US_DRIVER_LICENSE"), "a bare digit run with no context must not be flagged as a license, got {bare:?}");

        let with_context = scanner.scan("DL# 481349481");
        assert!(with_context.iter().any(|f| f.match_name == "US_DRIVER_LICENSE"), "expected a driver's license finding with 'DL#' context, got {with_context:?}");
    }

    #[test]
    fn test_medicare_mbi_dashed_form_detected_unconditionally_and_upgraded_with_context() {
        let scanner = PiiScanner::new();
        // CMS's own published example format, dashes for display.
        let without_context = scanner.scan("Reference: 1EG4-TE5-MK73");
        let f = without_context.iter().find(|f| f.match_name == "MEDICARE_MBI").expect("dashed MBI shape must be flagged even without context, got a miss");
        assert_eq!(f.severity, "MEDIUM");

        let with_context = scanner.scan("Your Medicare number (MBI) is 1EG4-TE5-MK73");
        let f2 = with_context.iter().find(|f| f.match_name == "MEDICARE_MBI").expect("expected an MBI finding");
        assert_eq!(f2.severity, "HIGH");
    }

    #[test]
    fn test_medicare_mbi_nodash_form_requires_context() {
        let scanner = PiiScanner::new();
        let bare = scanner.scan("Code: 1EG4TE5MK73");
        assert!(!bare.iter().any(|f| f.match_name == "MEDICARE_MBI"), "no-dash MBI shape must not be flagged without context, got {bare:?}");

        let with_context = scanner.scan("Beneficiary ID 1EG4TE5MK73 on file");
        assert!(with_context.iter().any(|f| f.match_name == "MEDICARE_MBI"), "expected an MBI finding with 'beneficiary' context, got {with_context:?}");
    }

    #[test]
    fn test_mbi_excluded_letters_never_match() {
        // The whole point of MBI's restricted alphabet (excludes B/I/L/O/S/Z)
        // is that a shape using one of those letters is NOT a valid MBI --
        // this is what makes the charset itself a structural signal.
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Your MBI is 1BG4-TE5-MK73"); // 'B' in position 2, excluded
        assert!(!findings.iter().any(|f| f.match_name == "MEDICARE_MBI"), "a shape using an excluded letter must not match the MBI pattern, got {findings:?}");
    }

    #[test]
    fn test_us_street_address_detected() {
        let scanner = PiiScanner::new();
        let findings = scanner.scan("Please ship to 1600 Pennsylvania Avenue");
        assert!(findings.iter().any(|f| f.match_name == "US_STREET_ADDRESS"), "expected a street address finding, got {findings:?}");
        assert!(findings.iter().any(|f| f.category == FindingCategory::Pii));

        let abbreviated = scanner.scan("I live at 221B Baker St");
        assert!(abbreviated.iter().any(|f| f.match_name == "US_STREET_ADDRESS"), "expected an abbreviated-suffix street address finding, got {abbreviated:?}");
    }

    #[test]
    fn test_bare_number_without_street_suffix_is_not_an_address() {
        let scanner = PiiScanner::new();
        let findings = scanner.scan("We sold 1600 units last quarter");
        assert!(!findings.iter().any(|f| f.match_name == "US_STREET_ADDRESS"), "a house-number-shaped prefix with no street suffix must not be flagged, got {findings:?}");
    }
}
