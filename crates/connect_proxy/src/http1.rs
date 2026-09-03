// Minimal HTTP/1.1 read/write for the TLS-terminated tunnel — deliberately
// not a general-purpose parser. Handles both Content-Length and chunked
// transfer-encoding on read (always re-framing as Content-Length on write,
// so the writer side never needs to emit chunked at all — a proxy is free
// to re-frame between the two as long as it fully buffers, which we already
// do for scanning). Known simplification vs. a full HTTP implementation:
// no request pipelining/keep-alive (one request/response per CONNECT
// tunnel) and no close-delimited (no Content-Length, no chunked, body runs
// until the connection closes) bodies — rare for JSON APIs, which always
// declare one framing or the other.

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct HttpMessage {
    /// Request line ("GET /v1/x HTTP/1.1") or status line ("HTTP/1.1 200 OK").
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Reads one request/response. Returns `Ok(None)` if the connection was
/// closed cleanly before any bytes of a new message arrived — the normal,
/// expected way a keep-alive tunnel ends, not an error. A connection that
/// closes mid-message still surfaces as an `Err` from the underlying read.
///
/// `allow_close_delimited` controls what happens when a message has neither
/// Content-Length nor chunked encoding: passing `true` reads the body until
/// the connection closes (the correct behavior for a *response*, and the
/// only way it's actually delimited per RFC 7230 §3.3.3 rule 7 — real-world
/// example: gemini.google.com's `/` response, live-confirmed 2026-08-04,
/// which was silently coming back as an empty body and rendering blank in
/// the browser). Passing `false` treats it as an empty body instead, which
/// is what a *request* with no framing header actually means (e.g. a plain
/// GET) — reading-to-EOF there would hang forever, since the client keeps
/// the tunnel open waiting for the response rather than closing it.
pub async fn read_message<R>(reader: &mut R, max_body: usize, allow_close_delimited: bool) -> Result<Option<HttpMessage>>
where
    R: AsyncBufRead + Unpin,
{
    let mut start_line = String::new();
    let n = reader.read_line(&mut start_line).await?;
    if n == 0 {
        return Ok(None);
    }
    let start_line = start_line.trim_end().to_string();
    if start_line.is_empty() {
        return Err(anyhow!("empty request/status line"));
    }

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_lowercase().contains("chunked"));

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let body = if is_chunked {
        read_chunked_body(reader, max_body).await?
    } else if let Some(content_length) = content_length {
        let content_length = content_length.min(max_body);
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await?;
        }
        body
    } else if allow_close_delimited {
        let mut body = Vec::new();
        reader.take(max_body as u64).read_to_end(&mut body).await?;
        body
    } else {
        Vec::new()
    };

    Ok(Some(HttpMessage { start_line, headers, body }))
}

/// Decodes a chunked-transfer-encoded body fully into memory: each chunk is
/// `<hex-size>[;ext]\r\n<data>\r\n`, terminated by a zero-size chunk
/// followed by an optional trailer section and a blank line.
async fn read_chunked_body<R>(reader: &mut R, max_body: usize) -> Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;
        let size_line = size_line.trim_end_matches(['\r', '\n']);
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| anyhow!("invalid chunk size line: {size_line:?}"))?;

        if chunk_size == 0 {
            // Optional trailer headers, then the terminating blank line.
            loop {
                let mut trailer_line = String::new();
                let n = reader.read_line(&mut trailer_line).await?;
                if n == 0 || trailer_line.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            break;
        }

        if body.len() + chunk_size > max_body {
            return Err(anyhow!("chunked body exceeds the {max_body}-byte limit"));
        }
        let mut chunk_data = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk_data).await?;
        body.extend_from_slice(&chunk_data);

        let mut trailing_crlf = [0u8; 2];
        reader.read_exact(&mut trailing_crlf).await?;
    }
    Ok(body)
}

pub async fn write_message<W>(writer: &mut W, message: &HttpMessage) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(message.body.len() + 256);
    out.extend_from_slice(message.start_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &message.headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue; // recomputed below in case the body was redacted to a different length
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", message.body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&message.body);

    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Parses a `CONNECT host:port HTTP/1.1` request line and consumes/discards
/// its headers, returning the target (host, port).
pub async fn read_connect_target<R>(reader: &mut R) -> Result<(String, u16)>
where
    R: AsyncBufRead + Unpin,
{
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim_end();

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("empty CONNECT request line"))?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(anyhow!("expected CONNECT, got {method}"));
    }
    let target = parts.next().ok_or_else(|| anyhow!("CONNECT request line missing target"))?;
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("CONNECT target {target} is not host:port"))?;
    let port: u16 = port.parse().map_err(|_| anyhow!("invalid port in CONNECT target: {target}"))?;

    // Discard headers up to the blank line.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }

    Ok((host.to_string(), port))
}

pub async fn write_connect_established<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a CONNECT response's status line when *we* are the one sending
/// CONNECT — chaining through an already-configured enterprise proxy (see
/// apps/tray's ExistingProxy::Manual) rather than dialing the destination
/// directly. Deliberately not `read_message`: a CONNECT response never has a
/// body, and `read_message`'s close-delimited fallback would otherwise try
/// to read-to-EOF and hang waiting for a connection that's about to start
/// carrying raw TLS bytes instead of closing.
pub async fn read_connect_response<R>(reader: &mut R) -> Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let mut status_line = String::new();
    let n = reader.read_line(&mut status_line).await?;
    if n == 0 {
        return Err(anyhow!("upstream proxy closed the connection before responding to CONNECT"));
    }
    let status_line = status_line.trim_end().to_string();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }

    Ok(status_line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn parses_connect_target_and_discards_headers() {
        let input = b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\nProxy-Connection: keep-alive\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let (host, port) = read_connect_target(&mut reader).await.unwrap();
        assert_eq!(host, "chatgpt.com");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn reads_a_request_with_a_body() {
        let input = b"POST /v1/chat HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"hello\":42}\n";
        let mut reader = BufReader::new(&input[..]);
        let msg = read_message(&mut reader, 1024, false).await.unwrap().unwrap();
        assert_eq!(msg.start_line, "POST /v1/chat HTTP/1.1");
        assert_eq!(msg.header("content-type"), Some("application/json"));
        assert_eq!(msg.body, b"{\"hello\":42}\n");
    }

    #[tokio::test]
    async fn writes_a_message_with_recomputed_content_length() {
        let msg = HttpMessage {
            start_line: "POST /v1/chat HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "999".to_string()), // stale, should be recomputed
            ],
            body: b"{\"a\":1}".to_vec(),
        };
        let mut out = Vec::new();
        write_message(&mut out, &msg).await.unwrap();
        let written = String::from_utf8(out).unwrap();
        assert!(written.contains("Content-Length: 7\r\n"));
        assert!(!written.contains("999"));
        assert!(written.ends_with("{\"a\":1}"));
    }

    #[tokio::test]
    async fn reads_a_chunked_request_body() {
        let input = b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n7\r\n{\"b\":2}\r\n0\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let msg = read_message(&mut reader, 1024, false).await.unwrap().unwrap();
        assert_eq!(msg.body, b"{\"a\":1}{\"b\":2}");
    }

    #[tokio::test]
    async fn reads_a_chunked_body_with_trailer_headers() {
        let input = b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: done\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let msg = read_message(&mut reader, 1024, false).await.unwrap().unwrap();
        assert_eq!(msg.body, b"hello");
    }

    #[tokio::test]
    async fn rejects_a_chunked_body_exceeding_the_max_size() {
        let input = b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        assert!(read_message(&mut reader, 2, false).await.is_err());
    }

    #[tokio::test]
    async fn clean_eof_before_a_message_returns_none_not_an_error() {
        let input: &[u8] = b"";
        let mut reader = BufReader::new(input);
        assert!(read_message(&mut reader, 1024, false).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn close_delimited_response_reads_body_until_eof_when_allowed() {
        // No Content-Length, no Transfer-Encoding -- real-world example:
        // gemini.google.com's own "/" response, live-confirmed 2026-08-04.
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>";
        let mut reader = BufReader::new(&input[..]);
        let msg = read_message(&mut reader, 1024, true).await.unwrap().unwrap();
        assert_eq!(msg.body, b"<html>hello</html>");
    }

    #[tokio::test]
    async fn close_delimited_request_is_treated_as_empty_when_disallowed() {
        // A request (e.g. a plain GET) with neither header means an empty
        // body, not "read until the client closes the tunnel" -- the client
        // keeps it open waiting for the response, so reading-to-EOF here
        // would hang forever instead.
        let input = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let msg = read_message(&mut reader, 1024, false).await.unwrap().unwrap();
        assert_eq!(msg.body, b"");
    }

    #[tokio::test]
    async fn reads_a_connect_response_status_line_and_discards_headers() {
        let input = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: some-corporate-proxy/1.0\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let status_line = read_connect_response(&mut reader).await.unwrap();
        assert_eq!(status_line, "HTTP/1.1 200 Connection Established");
    }

    #[tokio::test]
    async fn read_connect_response_surfaces_a_refusal() {
        let input = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let status_line = read_connect_response(&mut reader).await.unwrap();
        assert_eq!(status_line, "HTTP/1.1 407 Proxy Authentication Required");
    }
}
