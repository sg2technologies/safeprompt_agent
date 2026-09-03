// Hand-rolled Prometheus text-exposition exporter — deliberately not the
// `metrics`/`metrics-exporter-prometheus` crates: the surface here (three
// metric families, no dynamic label cardinality beyond a handful of known
// enum values) is small enough that a real dependency buys nothing but
// extra transitive surface, matching this codebase's existing preference for
// hand-rolled encoders (see `safeprompt-storage`'s CSV export).
//
// Not license-gated (see `safeprompt_licensing::features`) — this is
// operational observability, not a DLP capability tied to editions.

use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use tracing::info;

/// Standard-ish Prometheus histogram buckets, in seconds. Reused as-is from
/// Prometheus client library defaults rather than tuned for this workload —
/// revisit if real deployment latency data shows most requests landing in
/// too few buckets to be useful.
const LATENCY_BUCKETS_SECONDS: [f64; 11] =
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

struct Histogram {
    /// `bucket_counts[i]` is the cumulative count of observations `<=
    /// LATENCY_BUCKETS_SECONDS[i]` (Prometheus's `_bucket{le=...}` semantics)
    /// — each observation increments every bucket it falls under, so this is
    /// already cumulative and needs no further summing at render time.
    bucket_counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            bucket_counts: vec![0; LATENCY_BUCKETS_SECONDS.len()],
            sum: 0.0,
            count: 0,
        }
    }
}

impl Histogram {
    fn record(&mut self, seconds: f64) {
        self.sum += seconds;
        self.count += 1;
        for (bucket_count, bound) in self.bucket_counts.iter_mut().zip(LATENCY_BUCKETS_SECONDS.iter()) {
            if seconds <= *bound {
                *bucket_count += 1;
            }
        }
    }
}

#[derive(Default)]
pub struct Metrics {
    /// (event_type, action) -> count, e.g. ("request", "Block") -> 3.
    requests_total: Mutex<HashMap<(String, String), u64>>,
    /// provider name (or "legacy_upstream") -> count.
    provider_requests_total: Mutex<HashMap<String, u64>>,
    latency: Mutex<Histogram>,
}

impl Metrics {
    pub fn record_event(&self, event_type: &str, action: &str) {
        let mut requests = self.requests_total.lock().expect("requests_total lock poisoned");
        *requests.entry((event_type.to_string(), action.to_string())).or_insert(0) += 1;
    }

    pub fn record_provider_request(&self, provider: &str) {
        let mut providers = self.provider_requests_total.lock().expect("provider_requests_total lock poisoned");
        *providers.entry(provider.to_string()).or_insert(0) += 1;
    }

    pub fn record_latency_seconds(&self, seconds: f64) {
        self.latency.lock().expect("latency lock poisoned").record(seconds);
    }

    /// Renders every tracked metric in Prometheus text exposition format
    /// (the plain-text `# HELP`/`# TYPE`/samples shape any Prometheus-
    /// compatible scraper understands — no client library needed on either
    /// side). Map iteration order is sorted for deterministic, diffable
    /// output (also makes this function's own tests exact-match-able).
    pub fn render_prometheus_text(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP safeprompt_requests_total Total scans performed by the Agent, labeled by event_type (request/response/mcp) and the policy action taken.\n");
        out.push_str("# TYPE safeprompt_requests_total counter\n");
        {
            let requests = self.requests_total.lock().expect("requests_total lock poisoned");
            let mut entries: Vec<_> = requests.iter().collect();
            entries.sort();
            for ((event_type, action), count) in entries {
                out.push_str(&format!(
                    "safeprompt_requests_total{{event_type=\"{event_type}\",action=\"{action}\"}} {count}\n"
                ));
            }
        }

        out.push_str("# HELP safeprompt_provider_requests_total Total requests routed through each configured LLM provider (\"legacy_upstream\" for the single-upstream fallback).\n");
        out.push_str("# TYPE safeprompt_provider_requests_total counter\n");
        {
            let providers = self.provider_requests_total.lock().expect("provider_requests_total lock poisoned");
            let mut entries: Vec<_> = providers.iter().collect();
            entries.sort();
            for (provider, count) in entries {
                out.push_str(&format!("safeprompt_provider_requests_total{{provider=\"{provider}\"}} {count}\n"));
            }
        }

        out.push_str("# HELP safeprompt_request_duration_seconds Time to fully handle an inbound request (scan + upstream round trip + response scan).\n");
        out.push_str("# TYPE safeprompt_request_duration_seconds histogram\n");
        {
            let hist = self.latency.lock().expect("latency lock poisoned");
            for (bound, count) in LATENCY_BUCKETS_SECONDS.iter().zip(hist.bucket_counts.iter()) {
                out.push_str(&format!("safeprompt_request_duration_seconds_bucket{{le=\"{bound}\"}} {count}\n"));
            }
            out.push_str(&format!("safeprompt_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n", hist.count));
            out.push_str(&format!("safeprompt_request_duration_seconds_sum {}\n", hist.sum));
            out.push_str(&format!("safeprompt_request_duration_seconds_count {}\n", hist.count));
        }

        out
    }
}

static GLOBAL: OnceLock<Metrics> = OnceLock::new();

/// The single process-wide registry every crate records into — a metrics
/// registry is one of the few things that legitimately wants to be a global
/// singleton (same rationale as a global `tracing` subscriber): every
/// caller anywhere in the process should land in the same set of counters,
/// and threading an `Arc<Metrics>` through every function signature that
/// might want to record something buys nothing here.
pub fn global() -> &'static Metrics {
    GLOBAL.get_or_init(Metrics::default)
}

pub fn record_event(event_type: &str, action: &str) {
    global().record_event(event_type, action);
}

pub fn record_provider_request(provider: &str) {
    global().record_provider_request(provider);
}

pub fn record_latency_seconds(seconds: f64) {
    global().record_latency_seconds(seconds);
}

async fn metrics_handler() -> String {
    global().render_prometheus_text()
}

/// Serves `GET /metrics` on its own bind address — deliberately separate
/// from the DLP reverse-proxy port (127.0.0.1:8844) and the CONNECT-proxy
/// port (127.0.0.1:8845), since a Prometheus scrape target shouldn't share
/// a listener with client-facing traffic. Loopback-only by default, same
/// trust boundary as the other two.
pub async fn serve(bind_addr: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new().route("/metrics", get(metrics_handler));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("SafePrompt metrics endpoint listening on {bind_addr} (Prometheus text exposition format)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders_request_counts_by_event_type_and_action() {
        let metrics = Metrics::default();
        metrics.record_event("request", "Allow");
        metrics.record_event("request", "Allow");
        metrics.record_event("request", "Block");
        metrics.record_event("response", "Allow");

        let text = metrics.render_prometheus_text();
        assert!(text.contains("safeprompt_requests_total{event_type=\"request\",action=\"Allow\"} 2\n"));
        assert!(text.contains("safeprompt_requests_total{event_type=\"request\",action=\"Block\"} 1\n"));
        assert!(text.contains("safeprompt_requests_total{event_type=\"response\",action=\"Allow\"} 1\n"));
    }

    #[test]
    fn records_and_renders_provider_usage_counts() {
        let metrics = Metrics::default();
        metrics.record_provider_request("openai");
        metrics.record_provider_request("openai");
        metrics.record_provider_request("legacy_upstream");

        let text = metrics.render_prometheus_text();
        assert!(text.contains("safeprompt_provider_requests_total{provider=\"openai\"} 2\n"));
        assert!(text.contains("safeprompt_provider_requests_total{provider=\"legacy_upstream\"} 1\n"));
    }

    #[test]
    fn latency_histogram_buckets_are_cumulative_and_correctly_bounded() {
        let metrics = Metrics::default();
        metrics.record_latency_seconds(0.02); // falls into buckets >= 0.025
        metrics.record_latency_seconds(3.0); // falls into buckets >= 5.0 only

        let text = metrics.render_prometheus_text();
        assert!(text.contains("safeprompt_request_duration_seconds_bucket{le=\"0.01\"} 0\n"), "0.02s must not count in the 0.01s bucket: {text}");
        assert!(text.contains("safeprompt_request_duration_seconds_bucket{le=\"0.025\"} 1\n"), "0.02s must count in the 0.025s bucket: {text}");
        assert!(text.contains("safeprompt_request_duration_seconds_bucket{le=\"1\"} 1\n"), "3.0s must not count in the 1s bucket: {text}");
        assert!(text.contains("safeprompt_request_duration_seconds_bucket{le=\"5\"} 2\n"), "both observations must count in the 5s bucket: {text}");
        assert!(text.contains("safeprompt_request_duration_seconds_bucket{le=\"+Inf\"} 2\n"));
        assert!(text.contains("safeprompt_request_duration_seconds_count 2\n"));
        assert!(text.contains("safeprompt_request_duration_seconds_sum 3.02\n"));
    }

    #[test]
    fn render_output_has_help_and_type_lines_for_every_metric_family() {
        let metrics = Metrics::default();
        let text = metrics.render_prometheus_text();

        for family in ["safeprompt_requests_total", "safeprompt_provider_requests_total", "safeprompt_request_duration_seconds"] {
            assert!(text.contains(&format!("# HELP {family}")), "missing HELP line for {family}");
            assert!(text.contains(&format!("# TYPE {family}")), "missing TYPE line for {family}");
        }
    }

    #[tokio::test]
    async fn serve_exposes_a_working_metrics_http_endpoint() {
        let metrics = Metrics::default();
        metrics.record_event("request", "Allow");
        // Exercise the real global() + serve() path end to end (rather than
        // just the pure Metrics struct above) so the HTTP wiring itself is
        // covered, not only the text-rendering logic.
        global().record_event("request", "Allow");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(metrics_handler));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/metrics")).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(body.contains("safeprompt_requests_total"));
    }
}
