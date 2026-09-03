// CONNECT proxy: browsers/apps configured with this as their HTTPS proxy
// send `CONNECT host:port`. AI domains (sni_gate::is_ai_domain) get MITM'd
// with a per-hostname leaf cert from our CA so both the request AND
// response body can be scanned; everything else is an opaque byte relay —
// this proxy never terminates TLS for, or sees the content of, non-AI-domain
// traffic. See docs/SafeGateway-Architecture-Review.md §6/§6b for why this
// replaces PAC-file + extension-based browser coverage.
//
// Known simplifications (stated, not hidden): responses are scanned as a
// single fully-buffered message, not chunk-by-chunk like the reverse
// proxy's SSE path (fine here — see http1.rs, chunked bodies are already
// fully decoded before we ever see them); the client tunnel is kept alive
// across multiple sequential requests, but each gets its own fresh upstream
// TLS connection rather than reusing one (no upstream connection pooling
// yet); no true HTTP pipelining (requests are still handled one at a time,
// in order, not concurrently).

use crate::ca::CertificateAuthority;
use crate::http1::{self, HttpMessage};
use crate::sni_gate::{is_ai_domain, matches_domain_list};
use bytes::Bytes;
use futures_util::stream;
use rustls_pki_types::ServerName;
use safeprompt_common::{Action, ScanResult};
use safeprompt_inspector::Inspector;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info, warn};

const MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

pub struct ConnectProxyServer {
    bind_addr: SocketAddr,
    ca: Arc<CertificateAuthority>,
    inspector: Arc<Inspector>,
    /// Test-only hook: pin a hostname to a specific upstream address instead
    /// of resolving it for real. Not exposed to production callers.
    upstream_override: Option<HashMap<String, SocketAddr>>,
    /// Test-only hook: trust a custom root store when connecting to the
    /// upstream instead of the real public webpki roots.
    upstream_root_store: Option<Arc<rustls::RootCertStore>>,
    /// Where apps/tray records an already-configured enterprise proxy to
    /// chain through (see its `ExistingProxy::Manual`). A plain field
    /// (not a test-only hook) re-read per connection — cheap, and the
    /// simplest way to pick up changes without extra hot-reload plumbing.
    /// Injectable so tests can point it at a throwaway path instead of the
    /// real `%ProgramData%`.
    chain_target_path: PathBuf,
}

impl ConnectProxyServer {
    pub fn new(bind_addr: SocketAddr, ca: Arc<CertificateAuthority>, inspector: Arc<Inspector>) -> Self {
        let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        Self {
            bind_addr,
            ca,
            inspector,
            upstream_override: None,
            upstream_root_store: None,
            chain_target_path: PathBuf::from(program_data).join("SafePrompt").join("upstream-proxy.txt"),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        self.serve(listener).await
    }

    /// Split out from `run()` so tests can bind their own listener and read
    /// its OS-assigned port with zero gap before handing it here — binding
    /// separately then rebinding the same `SocketAddr` (bind, read port,
    /// drop, rebind) is a real TOCTOU race under load, not just a test nit.
    async fn serve(&self, listener: TcpListener) -> anyhow::Result<()> {
        info!("SafePrompt CONNECT proxy listening on {}", listener.local_addr()?);
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!("failed to accept a connection: {e}");
                    continue;
                }
            };
            let ca = Arc::clone(&self.ca);
            let inspector = Arc::clone(&self.inspector);
            let upstream_override = self.upstream_override.clone();
            let upstream_root_store = self.upstream_root_store.clone();
            let chain_target_path = self.chain_target_path.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, ca, inspector, upstream_override, upstream_root_store, chain_target_path).await {
                    warn!("connection from {peer} ended with an error: {e}");
                }
            });
        }
    }
}

fn upstream_proxy_chain_target(chain_target_path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(chain_target_path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

async fn connect_upstream(
    host: &str,
    port: u16,
    upstream_override: &Option<HashMap<String, SocketAddr>>,
    chain_target_path: &Path,
) -> anyhow::Result<TcpStream> {
    if let Some(addr) = upstream_override.as_ref().and_then(|m| m.get(host)) {
        return Ok(TcpStream::connect(addr).await?);
    }
    if let Some(proxy_hostport) = upstream_proxy_chain_target(chain_target_path) {
        return connect_via_upstream_proxy(&proxy_hostport, host, port).await;
    }
    Ok(TcpStream::connect((host, port)).await?)
}

/// Chains through an already-configured enterprise proxy rather than
/// dialing `host` directly, so SafePrompt sits *in front of* whatever
/// existing proxy/DLP/CASB stack the endpoint already had instead of
/// silently replacing it for every site — not just AI ones. Flagged in
/// architecture review 2026-08-04: naively taking over the browser's proxy
/// setting would otherwise break auth or egress policy for all the other
/// traffic this agent doesn't even inspect. Used by both the MITM path
/// (AI domains) and the opaque relay path (everything else) via the shared
/// `connect_upstream` above.
async fn connect_via_upstream_proxy(proxy_hostport: &str, host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_hostport)
        .await
        .map_err(|e| anyhow::anyhow!("failed to reach the upstream proxy {proxy_hostport}: {e}"))?;

    let connect_line = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(connect_line.as_bytes()).await?;

    let mut buffered = BufReader::new(stream);
    let status_line = http1::read_connect_response(&mut buffered).await?;
    if !status_line.contains("200") {
        return Err(anyhow::anyhow!("upstream proxy {proxy_hostport} refused CONNECT {host}:{port}: {status_line}"));
    }
    Ok(buffered.into_inner())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    ca: Arc<CertificateAuthority>,
    inspector: Arc<Inspector>,
    upstream_override: Option<HashMap<String, SocketAddr>>,
    upstream_root_store: Option<Arc<rustls::RootCertStore>>,
    chain_target_path: PathBuf,
) -> anyhow::Result<()> {
    let mut client = BufReader::new(stream);
    let (host, port) = http1::read_connect_target(&mut client).await?;
    http1::write_connect_established(&mut client).await?;

    // Two sources decide MITM-and-scan vs. opaque relay: the small built-in
    // AI_DOMAINS list, and the live policy-driven list a tenant admin can
    // extend with no rebuild (see sni_gate.rs's own doc comment for why
    // these are deliberately separate lists, not one).
    let policy_domains = inspector.connect_proxy_domains();
    if is_ai_domain(&host) || matches_domain_list(&host, &policy_domains) {
        intercept_and_scan(client, &host, port, &ca, &inspector, &upstream_override, &upstream_root_store, &chain_target_path).await
    } else {
        relay_opaque(client, &host, port, &upstream_override, &chain_target_path).await
    }
}

async fn relay_opaque<S>(
    mut client: S,
    host: &str,
    port: u16,
    upstream_override: &Option<HashMap<String, SocketAddr>>,
    chain_target_path: &Path,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = connect_upstream(host, port, upstream_override, chain_target_path).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Handles every request the browser sends on one CONNECT tunnel — browsers
/// commonly reuse a tunnel for several sequential requests, so treating it
/// as one-shot would silently drop everything after the first exchange.
/// Each request still gets a fresh upstream TLS connection (no upstream
/// connection pooling yet — stated simplification, correct but not
/// maximally efficient).
/// AGENT-FILE-001: real browser file/image uploads to ChatGPT/Claude/etc.
/// route through here -- the CONNECT-proxy is the only interception point
/// that actually sees this traffic (the extension has no file-handling
/// code at all; see browser-extension/src/main-world-interceptor.js).
/// Ported from `safeprompt-proxy::scan_multipart_request` (the API
/// Gateway's own multipart handler) rather than inventing new detection
/// logic -- same extract-then-OCR-then-scan pipeline, same "Redact
/// upgrades to Block" reasoning (there's no safe way to splice sanitized
/// text back into a binary multipart body -- a redacted passport photo
/// isn't a photo anymore), same policy-driven `upload_action()` pre-check,
/// same fail-open posture for a file type `safeprompt-file-inspector`
/// can't parse (logged, not held against the request).
async fn scan_multipart_request(inspector: &Inspector, content_type: &str, body: &[u8]) -> ScanResult {
    let boundary = match multer::parse_boundary(content_type) {
        Ok(b) => b,
        Err(e) => {
            warn!("multipart request had no parseable boundary: {e}");
            return inspector.inspect("");
        }
    };

    let owned_body = Bytes::copy_from_slice(body);
    let body_stream = stream::once(futures_util::future::ready(Ok::<Bytes, std::io::Error>(owned_body)));
    let mut multipart = multer::Multipart::new(body_stream, boundary);

    let mut combined_text = String::new();

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                warn!("multipart parse error mid-stream: {e}");
                break;
            }
        };

        if let Some(filename) = field.file_name().map(str::to_string) {
            let extension = filename.rsplit('.').next().unwrap_or("");
            match inspector.upload_action(extension) {
                safeprompt_policy::UploadAction::Block => {
                    warn!("upload '{filename}' blocked by policy for extension '.{extension}'");
                    return ScanResult {
                        action: Action::Block,
                        findings: Vec::new(),
                        original_prompt: String::new(),
                        sanitized_prompt: String::new(),
                        unmaskable_reason: None,
                    };
                }
                safeprompt_policy::UploadAction::Allow => {
                    info!("upload '{filename}' allowed unscanned per policy for extension '.{extension}'");
                    continue;
                }
                safeprompt_policy::UploadAction::Inspect => {}
            }

            let file_bytes = match field.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("failed reading multipart file field '{filename}': {e}");
                    continue;
                }
            };
            match safeprompt_file_inspector::extract_text(&filename, &file_bytes, inspector.ocr_engine()) {
                safeprompt_file_inspector::ExtractionOutcome::Text(text) => {
                    combined_text.push_str(&text);
                    combined_text.push('\n');
                }
                safeprompt_file_inspector::ExtractionOutcome::Unsupported { filename, reason } => {
                    warn!("uploaded file '{filename}' could not be scanned ({reason}) — allowed through unscanned");
                }
            }
        } else if let Ok(text) = field.text().await {
            combined_text.push_str(&text);
            combined_text.push('\n');
        }
    }

    let mut scan = inspector.inspect(&combined_text);
    if scan.action == Action::Redact {
        scan.action = Action::Block;
    }
    scan
}

#[allow(clippy::too_many_arguments)]
async fn intercept_and_scan<S>(
    client: S,
    host: &str,
    port: u16,
    ca: &CertificateAuthority,
    inspector: &Inspector,
    upstream_override: &Option<HashMap<String, SocketAddr>>,
    upstream_root_store: &Option<Arc<rustls::RootCertStore>>,
    chain_target_path: &Path,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (leaf_cert, leaf_key) = ca.issue_leaf_cert(host)?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert], leaf_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_tls = acceptor.accept(client).await?;
    let mut client_tls = BufReader::new(client_tls);

    loop {
        let Some(request) = http1::read_message(&mut client_tls, MAX_BODY_BYTES, false).await? else {
            return Ok(()); // client closed the tunnel — nothing left to do
        };

        // AGENT-FILE-001: a multipart body (real browser file/image upload)
        // gets parsed and OCR'd field-by-field rather than lossy-UTF8'd as
        // one blob -- binary image bytes decoded that way just produce
        // garbage that no regex/PII detector can ever match, which is
        // exactly how a passport photo used to sail through unscanned.
        let content_type = request.header("content-type").unwrap_or("").to_string();
        let scan = if content_type.to_ascii_lowercase().starts_with("multipart/form-data") {
            scan_multipart_request(inspector, &content_type, &request.body).await
        } else {
            let body_text = String::from_utf8_lossy(&request.body).into_owned();
            inspector.inspect(&body_text)
        };

        // .enforcement_action() so a RequireApproval decision -- no approval
        // queue exists yet, SP-RISK-004 -- fails closed instead of silently
        // falling through as an allow (see Action::enforcement_action's own
        // doc comment in safeprompt-common).
        if scan.action.enforcement_action() == Action::Block {
            warn!(host, findings = scan.findings.len(), "browser AI request blocked by SafePrompt policy");
            let response = HttpMessage {
                start_line: "HTTP/1.1 403 Forbidden".to_string(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: format!(
                    "{{\"error\":{{\"message\":\"Request blocked by SafePrompt policy\",\"finding_count\":{}}}}}",
                    scan.findings.len()
                )
                .into_bytes(),
            };
            http1::write_message(&mut client_tls, &response).await?;
            continue; // tunnel stays open for the next request
        }

        let outgoing_body = if scan.action == Action::Redact {
            info!(host, findings = scan.findings.len(), "browser AI request redacted by SafePrompt policy");
            scan.sanitized_prompt.into_bytes()
        } else {
            request.body
        };
        let outgoing_request = HttpMessage { body: outgoing_body, ..request };

        let root_store = match upstream_root_store {
            Some(store) => (**store).clone(),
            None => rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        };
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(host.to_string())?;
        let upstream_tcp = connect_upstream(host, port, upstream_override, chain_target_path).await?;
        let upstream_tls = connector.connect(server_name, upstream_tcp).await?;
        let mut upstream_tls = BufReader::new(upstream_tls);

        http1::write_message(&mut upstream_tls, &outgoing_request).await?;
        let Some(response) = http1::read_message(&mut upstream_tls, MAX_BODY_BYTES, true).await? else {
            return Err(anyhow::anyhow!("upstream closed the connection without responding"));
        };

        let response_text = String::from_utf8_lossy(&response.body).into_owned();
        let response_scan = inspector.inspect_response(&response_text);

        // See the request-scan block above for enforcement_action()'s reasoning.
        let outgoing_response = if response_scan.action.enforcement_action() == Action::Block {
            warn!(host, findings = response_scan.findings.len(), "browser AI response blocked by SafePrompt policy");
            HttpMessage {
                start_line: "HTTP/1.1 403 Forbidden".to_string(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: format!(
                    "{{\"error\":{{\"message\":\"Response blocked by SafePrompt policy\",\"finding_count\":{}}}}}",
                    response_scan.findings.len()
                )
                .into_bytes(),
            }
        } else if response_scan.action == Action::Redact {
            info!(host, findings = response_scan.findings.len(), "browser AI response redacted by SafePrompt policy");
            HttpMessage {
                body: response_scan.sanitized_prompt.into_bytes(),
                ..response
            }
        } else {
            response
        };

        http1::write_message(&mut client_tls, &outgoing_response).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeprompt_policy::PolicyConfig;
    use tokio_rustls::TlsAcceptor as TestTlsAcceptor;

    /// Mock "claude.ai" upstream: TLS-terminates with a leaf cert from the
    /// given CA, replies with `response_body` to every request. Loops
    /// accepting connections, since `intercept_and_scan` opens a fresh
    /// upstream TLS connection per request even when the client reuses one
    /// CONNECT tunnel for several.
    async fn spawn_mock_ai_upstream(ca: &CertificateAuthority, hostname: &str, response_body: &'static [u8]) -> SocketAddr {
        let (cert, key) = ca.issue_leaf_cert(hostname).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TestTlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = acceptor.accept(stream).await.unwrap();
                    let mut tls_stream = BufReader::new(tls_stream);
                    let _request = http1::read_message(&mut tls_stream, MAX_BODY_BYTES, false).await.unwrap().unwrap();
                    let response = HttpMessage {
                        start_line: "HTTP/1.1 200 OK".to_string(),
                        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                        body: response_body.to_vec(),
                    };
                    http1::write_message(&mut tls_stream, &response).await.unwrap();
                });
            }
        });

        addr
    }

    /// A path that deliberately never exists, so `connect_upstream` falls
    /// through to a direct connection — the default for every test except
    /// the ones in this module that specifically exercise chaining.
    fn no_chain_target_path() -> PathBuf {
        std::env::temp_dir().join("safeprompt-connect-proxy-tests-no-chain-configured.txt")
    }

    fn root_store_trusting(ca: &CertificateAuthority) -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        store.add(ca.root_cert_der()).unwrap();
        Arc::new(store)
    }

    async fn spawn_test_proxy(ca: Arc<CertificateAuthority>, ai_upstream_addr: SocketAddr, hostname: &str) -> SocketAddr {
        spawn_test_proxy_with_inspector(ca, ai_upstream_addr, hostname, Arc::new(Inspector::new(PolicyConfig::default()))).await
    }

    /// Same as `spawn_test_proxy`, but with an explicit `Inspector` instead
    /// of always defaulting to `PolicyConfig::default()` -- lets tests
    /// exercise the policy-driven `connect_proxy_domains` gating path with a
    /// hostname that isn't the hardcoded `AI_DOMAINS` test fixture.
    async fn spawn_test_proxy_with_inspector(
        ca: Arc<CertificateAuthority>,
        ai_upstream_addr: SocketAddr,
        hostname: &str,
        inspector: Arc<Inspector>,
    ) -> SocketAddr {
        let mut overrides = HashMap::new();
        overrides.insert(hostname.to_string(), ai_upstream_addr);

        let root_store = root_store_trusting(&ca);
        let server = ConnectProxyServer {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // unused once we call serve() directly
            ca,
            inspector,
            upstream_override: Some(overrides),
            upstream_root_store: Some(root_store),
            chain_target_path: no_chain_target_path(),
        };

        // Bind directly and hand the already-listening socket to serve() —
        // no bind/read-port/drop/rebind gap, so no TOCTOU race under load
        // (the OS queues the test client's connection in the accept
        // backlog the instant bind() completes, even before the spawned
        // task below gets scheduled to actually call accept()).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            server.serve(listener).await.unwrap();
        });
        proxy_addr
    }

    /// Acts as the "browser": CONNECTs through the proxy, completes a TLS
    /// handshake trusting `ca`, sends one request, returns the response.
    async fn send_through_proxy(
        proxy_addr: SocketAddr,
        hostname: &str,
        ca: &CertificateAuthority,
        body: &str,
    ) -> HttpMessage {
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut stream = BufReader::new(stream);
        let connect_line = format!("CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_line.as_bytes()).await.unwrap();
        let established = http1::read_message(&mut stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();
        assert!(established.start_line.contains("200"), "expected CONNECT to succeed: {}", established.start_line);

        let root_store = root_store_trusting(ca);
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates((*root_store).clone())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(hostname.to_string()).unwrap();
        let tls_stream = connector.connect(server_name, stream).await.unwrap();
        let mut tls_stream = BufReader::new(tls_stream);

        let request = HttpMessage {
            start_line: "POST /v1/chat/completions HTTP/1.1".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: body.as_bytes().to_vec(),
        };
        http1::write_message(&mut tls_stream, &request).await.unwrap();
        http1::read_message(&mut tls_stream, MAX_BODY_BYTES, true).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn keeps_the_tunnel_alive_across_multiple_sequential_requests() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"hello from the mock AI upstream"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut stream = BufReader::new(stream);
        let connect_line = "CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_line.as_bytes()).await.unwrap();
        http1::read_message(&mut stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();

        let root_store = root_store_trusting(&ca);
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates((*root_store).clone())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("claude.ai".to_string()).unwrap();
        let tls_stream = connector.connect(server_name, stream).await.unwrap();
        let mut tls_stream = BufReader::new(tls_stream);

        // Three requests, one TLS connection: clean, blocked, clean again —
        // proves the tunnel survives a block and keeps serving afterward.
        for body in [
            r#"{"messages":[{"role":"user","content":"hello"}]}"#,
            r#"{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}"#,
            r#"{"messages":[{"role":"user","content":"still here?"}]}"#,
        ] {
            let request = HttpMessage {
                start_line: "POST /v1/chat/completions HTTP/1.1".to_string(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: body.as_bytes().to_vec(),
            };
            http1::write_message(&mut tls_stream, &request).await.unwrap();
            let response = http1::read_message(&mut tls_stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();

            if body.contains("AKIA") {
                assert!(response.start_line.contains("403"), "expected the secret-carrying request to be blocked");
            } else {
                assert!(response.start_line.contains("200"), "expected {body:?} to succeed, got {}", response.start_line);
            }
        }
    }

    #[tokio::test]
    async fn allows_and_forwards_a_clean_browser_ai_request() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"hello from the mock AI upstream"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let response = send_through_proxy(proxy_addr, "claude.ai", &ca, r#"{"messages":[{"role":"user","content":"hello"}]}"#).await;

        assert!(response.start_line.contains("200"), "expected 200, got {}", response.start_line);
        assert!(String::from_utf8_lossy(&response.body).contains("hello from the mock AI upstream"));
    }

    #[tokio::test]
    async fn blocks_a_browser_ai_request_containing_a_secret_before_it_reaches_upstream() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"hello from the mock AI upstream"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let response = send_through_proxy(
            proxy_addr,
            "claude.ai",
            &ca,
            r#"{"messages":[{"role":"user","content":"here is my key AKIAIOSFODNN7EXAMPLE"}]}"#,
        )
        .await;

        assert!(response.start_line.contains("403"), "expected 403, got {}", response.start_line);
        assert!(!String::from_utf8_lossy(&response.body).contains("hello from the mock AI upstream"));
    }

    /// Builds a minimal, valid multipart/form-data body with one file field
    /// -- deliberately hand-rolled rather than pulling in reqwest's
    /// multipart builder as a new dev-dependency, since the point is
    /// exercising `multer`'s parser (the same one production traffic hits),
    /// not a second HTTP client.
    fn multipart_body_with_one_file(filename: &str, file_contents: &str) -> (String, Vec<u8>) {
        let boundary = "SafePromptTestBoundary123456";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n{file_contents}\r\n--{boundary}--\r\n"
        );
        (format!("multipart/form-data; boundary={boundary}"), body.into_bytes())
    }

    async fn send_multipart_through_proxy(
        proxy_addr: SocketAddr,
        hostname: &str,
        ca: &CertificateAuthority,
        content_type: &str,
        body: Vec<u8>,
    ) -> HttpMessage {
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut stream = BufReader::new(stream);
        let connect_line = format!("CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_line.as_bytes()).await.unwrap();
        let established = http1::read_message(&mut stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();
        assert!(established.start_line.contains("200"), "expected CONNECT to succeed: {}", established.start_line);

        let root_store = root_store_trusting(ca);
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates((*root_store).clone())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(hostname.to_string()).unwrap();
        let tls_stream = connector.connect(server_name, stream).await.unwrap();
        let mut tls_stream = BufReader::new(tls_stream);

        let request = HttpMessage {
            start_line: "POST /backend-api/upload HTTP/1.1".to_string(),
            headers: vec![("Content-Type".to_string(), content_type.to_string())],
            body,
        };
        http1::write_message(&mut tls_stream, &request).await.unwrap();
        http1::read_message(&mut tls_stream, MAX_BODY_BYTES, true).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn blocks_a_browser_file_upload_containing_a_secret() {
        // AGENT-FILE-001 regression: before this fix, a multipart body was
        // decoded as lossy UTF-8 and scanned as one blob -- a real image's
        // binary bytes never matched anything, so a file upload's contents
        // (an uploaded passport photo, in the case that surfaced this) sailed
        // through completely unscanned. A .txt file needs no OCR to prove the
        // multipart-parse-then-scan wiring itself is now correct end to end;
        // OCR-specific extraction is already covered by safeprompt-file-inspector's
        // own tests.
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"hello from the mock AI upstream"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let (content_type, body) = multipart_body_with_one_file("secret.txt", "here is my key AKIAIOSFODNN7EXAMPLE");
        let response = send_multipart_through_proxy(proxy_addr, "claude.ai", &ca, &content_type, body).await;

        assert!(response.start_line.contains("403"), "expected 403, got {}", response.start_line);
        assert!(!String::from_utf8_lossy(&response.body).contains("hello from the mock AI upstream"));
    }

    #[tokio::test]
    async fn allows_a_clean_browser_file_upload_and_forwards_it() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"hello from the mock AI upstream"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let (content_type, body) = multipart_body_with_one_file("notes.txt", "just a normal agenda, nothing sensitive");
        let response = send_multipart_through_proxy(proxy_addr, "claude.ai", &ca, &content_type, body).await;

        assert!(response.start_line.contains("200"), "expected 200, got {}", response.start_line);
        assert!(String::from_utf8_lossy(&response.body).contains("hello from the mock AI upstream"));
    }

    #[tokio::test]
    async fn blocks_a_browser_ai_response_containing_a_secret() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        // The mock upstream's reply itself contains a secret this time —
        // request is clean, so this proves the *response* leg is scanned.
        let ai_upstream_addr = spawn_mock_ai_upstream(
            &ca,
            "claude.ai",
            br#"{"reply":"here is AKIAIOSFODNN7EXAMPLE for you"}"#,
        )
        .await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let response = send_through_proxy(proxy_addr, "claude.ai", &ca, r#"{"messages":[{"role":"user","content":"hi"}]}"#).await;

        assert!(response.start_line.contains("403"), "expected 403, got {}", response.start_line);
        assert!(!String::from_utf8_lossy(&response.body).contains("AKIAIOSFODNN7EXAMPLE"), "secret must never reach the client");
    }

    #[tokio::test]
    async fn redacts_pii_in_a_browser_ai_response() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"contact user@example.com"}"#).await;
        let proxy_addr = spawn_test_proxy(Arc::clone(&ca), ai_upstream_addr, "claude.ai").await;

        let response = send_through_proxy(proxy_addr, "claude.ai", &ca, r#"{"messages":[{"role":"user","content":"hi"}]}"#).await;

        assert!(response.start_line.contains("200"), "expected 200, got {}", response.start_line);
        let body = String::from_utf8_lossy(&response.body);
        assert!(!body.contains("user@example.com"));
        assert!(body.contains("REDACTED_EMAIL"));
    }

    #[tokio::test]
    async fn relays_non_ai_domains_opaquely_without_terminating_tls() {
        // A plain TCP echo server standing in for an arbitrary non-AI site —
        // if the proxy tried to MITM this, the TLS handshake below would
        // fail; succeeding proves it went through as an untouched byte relay.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buf[..n]).await.unwrap();
        });

        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let mut overrides = HashMap::new();
        overrides.insert("example.com".to_string(), echo_addr);
        let server = ConnectProxyServer {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // unused once we call serve() directly
            ca,
            inspector,
            upstream_override: Some(overrides),
            upstream_root_store: None,
            chain_target_path: no_chain_target_path(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            server.serve(listener).await.unwrap();
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut stream = BufReader::new(stream);
        let connect_line = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_line.as_bytes()).await.unwrap();
        let established = http1::read_message(&mut stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();
        assert!(established.start_line.contains("200"));

        tokio::io::AsyncWriteExt::write_all(&mut stream, b"plain bytes, no TLS here").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"plain bytes, no TLS here");
    }

    fn application_policy(id: &str, domain: &str, connect_proxy: bool) -> safeprompt_policy::ApplicationPolicy {
        safeprompt_policy::ApplicationPolicy {
            id: id.to_string(),
            match_domains: vec![domain.to_string()],
            enabled: true,
            upload: true,
            prompt_scan: true,
            response_scan: true,
            connect_proxy,
        }
    }

    #[tokio::test]
    async fn a_policy_driven_domain_opted_into_connect_proxy_gets_mitm_and_scanned() {
        // A domain that is NOT in the built-in AI_DOMAINS list at all --
        // proves coverage comes purely from the live policy
        // (ApplicationPolicy::connect_proxy), not the hardcoded constant.
        let hostname = "llm.internal.example.com";
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr =
            spawn_mock_ai_upstream(&ca, hostname, br#"{"reply":"hello from the internal tool"}"#).await;
        let policy = PolicyConfig {
            applications: vec![application_policy("internal-llm", hostname, true)],
            ..PolicyConfig::default()
        };
        let inspector = Arc::new(Inspector::new(policy));
        let proxy_addr = spawn_test_proxy_with_inspector(Arc::clone(&ca), ai_upstream_addr, hostname, inspector).await;

        // Same secret-blocking proof the AI_DOMAINS-based tests above use:
        // a 403 here can only happen if the proxy actually decrypted and
        // scanned the request, i.e. genuinely took the MITM path.
        let response = send_through_proxy(
            proxy_addr,
            hostname,
            &ca,
            r#"{"messages":[{"role":"user","content":"here is my key AKIAIOSFODNN7EXAMPLE"}]}"#,
        )
        .await;
        assert!(response.start_line.contains("403"), "expected the policy-covered domain to be scanned and blocked, got {}", response.start_line);
    }

    #[tokio::test]
    async fn a_policy_entry_that_does_not_opt_into_connect_proxy_stays_an_opaque_relay() {
        // The critical regression guard: an ApplicationPolicy entry that
        // exists purely to govern browser-extension behavior (enabled:
        // true, connect_proxy: false/omitted -- the shape a real "chatgpt"/
        // "claude" entry has today) must NOT cause the CONNECT proxy to
        // attempt MITM. If it did, this would silently resurrect the exact
        // bot-detection-blocking bug sni_gate.rs's own doc comment describes
        // fixing, the moment any tenant policy lists a major AI vendor for
        // extension-side governance (an entirely ordinary thing to do).
        let hostname = "llm.internal.example.com";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &buf[..n]).await.unwrap();
        });

        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let policy = PolicyConfig {
            applications: vec![application_policy("chatgpt-like-entry", hostname, false)],
            ..PolicyConfig::default()
        };
        let inspector = Arc::new(Inspector::new(policy));
        let proxy_addr = spawn_test_proxy_with_inspector(Arc::clone(&ca), echo_addr, hostname, inspector).await;

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut stream = BufReader::new(stream);
        let connect_line = format!("CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut stream, connect_line.as_bytes()).await.unwrap();
        let established = http1::read_message(&mut stream, MAX_BODY_BYTES, true).await.unwrap().unwrap();
        assert!(established.start_line.contains("200"));

        // Plain (non-TLS) bytes surviving a round trip proves this went
        // through as an untouched byte relay, not MITM'd -- a MITM attempt
        // would try (and fail) to read a TLS ClientHello here instead.
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"plain bytes, no TLS here").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"plain bytes, no TLS here");
    }

    /// A minimal "corporate proxy" stand-in: accepts a CONNECT, replies 200,
    /// then relays bytes to `upstream_addr` — deliberately ignoring the
    /// requested host, since what's under test is whether SafePrompt's own
    /// `connect_upstream` correctly chains through an upstream CONNECT proxy
    /// at all, not DNS-based routing inside the mock proxy itself.
    async fn spawn_mock_corporate_proxy(upstream_addr: SocketAddr) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buffered = BufReader::new(stream);
                    let (_host, _port) = http1::read_connect_target(&mut buffered).await.unwrap();
                    http1::write_connect_established(&mut buffered).await.unwrap();
                    let mut client = buffered.into_inner();
                    let mut upstream = TcpStream::connect(upstream_addr).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn chains_through_an_existing_upstream_proxy_when_one_is_configured() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let ai_upstream_addr = spawn_mock_ai_upstream(&ca, "claude.ai", br#"{"reply":"via the corporate proxy"}"#).await;
        let corporate_proxy_addr = spawn_mock_corporate_proxy(ai_upstream_addr).await;

        // Stands in for the real upstream-proxy.txt apps/tray writes when it
        // detects an existing manual proxy (ExistingProxy::Manual) — unique
        // per test run so parallel tests can't collide on it.
        let chain_path = std::env::temp_dir().join(format!("safeprompt-connect-proxy-test-chain-{}.txt", std::process::id()));
        std::fs::write(&chain_path, corporate_proxy_addr.to_string()).unwrap();

        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let root_store = root_store_trusting(&ca);
        // Deliberately no upstream_override here: that test hook is checked
        // *before* chaining in connect_upstream and would bypass the code
        // path this test exists to exercise. The mock corporate proxy above
        // ignoring the requested host is what makes a real, DNS-free connect
        // safe to use instead.
        let server = ConnectProxyServer {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ca: Arc::clone(&ca),
            inspector,
            upstream_override: None,
            upstream_root_store: Some(root_store),
            chain_target_path: chain_path.clone(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            server.serve(listener).await.unwrap();
        });

        let response = send_through_proxy(proxy_addr, "claude.ai", &ca, r#"{"messages":[{"role":"user","content":"hi"}]}"#).await;
        let _ = std::fs::remove_file(&chain_path);

        assert!(response.start_line.contains("200"), "expected 200, got {}", response.start_line);
        assert!(String::from_utf8_lossy(&response.body).contains("via the corporate proxy"));
    }
}
