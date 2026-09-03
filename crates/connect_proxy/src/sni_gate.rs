// Port of backend/gateway/connect_proxy.py's `_AI_DOMAINS`/`_is_ai_domain` —
// only these domains get TLS-terminated and scanned; everything else is an
// opaque relay. This boundary is the thing to point at when a customer asks
// "what exactly do you decrypt" — see docs/SafeGateway-Architecture-Review.md §6.
//
// Two sources feed that boundary as of 2026-08-08: this file's own small
// built-in AI_DOMAINS constant below, AND a live, policy-driven domain list
// (`Inspector::connect_proxy_domains`, `ApplicationPolicy::connect_proxy`) a
// tenant admin can extend with no code change or rebuild — see
// `server.rs::handle_connection`, which consults both. Deliberately kept
// separate from `Inspector::enabled_application_domains` (the browser
// extension's own dynamic-site list): most `applications` policy entries
// exist purely to govern extension behavior for a site that would break
// under this proxy's own MITM (see AI_DOMAINS's doc comment right below),
// so a domain must opt in explicitly via `connect_proxy: true` rather than
// inheriting coverage just for being `enabled`.

// Empty as of 2026-08-05. Every major hosted AI chat site this proxy tried
// to MITM has, one at a time, turned out to sit behind bot detection that
// fingerprints *our own* outbound TLS handshake (not the browser's — a MITM
// proxy necessarily makes its own connection to the real upstream) and
// blocks/challenges it instead of serving the real site: chatgpt.com/
// openai.com (live-confirmed 2026-08-04), gemini.google.com (2026-08-05),
// then claude.ai/perplexity.ai the same day, live-confirmed via the exact
// same blank-page symptom. Rather than keep discovering this one domain at
// a time, grok.com/x.ai are pulled preemptively too — untested here, but
// there's no reason to expect a Cloudflare-fronted chat product to behave
// differently from the five that already failed the same way. DLP coverage
// for all of these comes from browser-extension/ instead, which runs
// inside the real browser and never makes its own network connection at
// all, so there's nothing for the upstream to fingerprint. This constant
// stays in place (rather than deleting is_ai_domain entirely) as the one
// place to point at when a customer asks "what exactly do you decrypt" —
// today the honest answer is "nothing by default," and any future non-
// major-vendor domain that doesn't run this kind of bot detection is a
// candidate to add back here.
#[cfg(not(test))]
const AI_DOMAINS: &[&str] = &[];

// server.rs's own tests use "claude.ai" purely as a synthetic fixture
// domain to exercise the MITM-and-scan code path (mock upstream, not the
// real claude.ai) -- that's independent of whether the real claude.ai
// belongs in the production list above, which it no longer does per the
// doc comment on is_ai_domain. Test builds get their own one-entry list so
// those tests keep exercising the real MITM path without adding a real
// domain back to what an actual release binary intercepts.
#[cfg(test)]
const AI_DOMAINS: &[&str] = &["claude.ai"];

pub fn is_ai_domain(host: &str) -> bool {
    matches_domain_list(host, AI_DOMAINS.iter().map(|d| d.to_string()).collect::<Vec<_>>().as_slice())
}

/// Exact-or-subdomain match against a runtime-supplied domain list — the
/// same matching rule `is_ai_domain` uses for the built-in `AI_DOMAINS`
/// constant, generalized so `server.rs` can apply it identically to the
/// live policy-driven list (`Inspector::connect_proxy_domains`) without
/// duplicating the suffix logic. `domains` entries are matched
/// case-insensitively, same as `host`.
pub fn matches_domain_list(host: &str, domains: &[String]) -> bool {
    let host = host.trim().to_lowercase();
    domains.iter().any(|d| {
        let d = d.trim().to_lowercase();
        host == d || host.ends_with(&format!(".{d}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_match_unrelated_hosts() {
        assert!(!is_ai_domain("example.com"));
        assert!(!is_ai_domain("notopenai.com"));
        assert!(!is_ai_domain("google.com"));
    }

    #[test]
    fn deliberately_excludes_every_major_ai_chat_site_except_the_test_fixture() {
        // See the doc comment above AI_DOMAINS: every one of these was
        // tried and live-confirmed to break (blank page / stuck connection)
        // behind bot detection that fingerprints this proxy's own outbound
        // TLS handshake. Coverage comes from browser-extension/ instead.
        // claude.ai is deliberately NOT asserted excluded here -- under
        // #[cfg(test)] it's the one-entry synthetic fixture domain
        // server.rs's own tests need to exercise the real MITM-and-scan
        // path (see the #[cfg(test)] AI_DOMAINS above); this crate's own
        // real production AI_DOMAINS is empty and excludes claude.ai too,
        // just not observable from inside a #[cfg(test)] build.
        assert!(!is_ai_domain("chatgpt.com"));
        assert!(!is_ai_domain("chat.openai.com"));
        assert!(!is_ai_domain("openai.com"));
        assert!(!is_ai_domain("gemini.google.com"));
        assert!(!is_ai_domain("anthropic.com"));
        assert!(!is_ai_domain("perplexity.ai"));
        assert!(!is_ai_domain("sub.perplexity.ai"));
        assert!(!is_ai_domain("grok.com"));
        assert!(!is_ai_domain("x.ai"));
    }

    #[test]
    fn test_fixture_domain_matches_exact_and_subdomain() {
        // The #[cfg(test)]-only AI_DOMAINS entry that keeps server.rs's own
        // MITM/scan-path tests exercising real logic instead of always
        // hitting the opaque-relay fallback.
        assert!(is_ai_domain("claude.ai"));
        assert!(is_ai_domain("CLAUDE.AI"));
        assert!(is_ai_domain("sub.claude.ai"));
    }

    #[test]
    fn matches_domain_list_handles_exact_subdomain_and_case() {
        let domains = vec!["llm.internal.example.com".to_string()];
        assert!(matches_domain_list("llm.internal.example.com", &domains));
        assert!(matches_domain_list("LLM.INTERNAL.EXAMPLE.COM", &domains));
        assert!(matches_domain_list("api.llm.internal.example.com", &domains));
        assert!(!matches_domain_list("notllm.internal.example.com", &domains));
        assert!(!matches_domain_list("example.com", &domains));
    }

    #[test]
    fn matches_domain_list_with_an_empty_list_matches_nothing() {
        assert!(!matches_domain_list("anything.example.com", &[]));
    }
}
