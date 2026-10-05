//! Bounded reading of HTTP response bodies.
//!
//! Error responses are only read to surface their cause in logs: a proxy
//! sending an endless (or huge) body must neither block the caller nor grow
//! its memory.

use std::time::Duration;

/// Reads at most `max_bytes` of the response body, for at most `deadline`.
///
/// Stops at the first of these limits (or at the end of the body, or on a
/// read error) and returns what was received; the result is truncated to
/// `max_bytes`.
pub(crate) async fn read_body_prefix(
    mut resp: reqwest::Response,
    max_bytes: usize,
    deadline: Duration,
) -> Vec<u8> {
    let mut body = Vec::new();
    let read = async {
        while body.len() < max_bytes {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    let room = max_bytes - body.len();
                    body.extend_from_slice(&chunk[..chunk.len().min(room)]);
                }
                Ok(None) | Err(_) => break,
            }
        }
    };
    // On timeout, keep what was read so far.
    let _ = tokio::time::timeout(deadline, read).await;
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The server is returned with the response: it must outlive the read.
    async fn response_with_body(body: Vec<u8>) -> (MockServer, reqwest::Response) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(502).set_body_bytes(body))
            .mount(&server)
            .await;
        let resp = reqwest::get(server.uri()).await.unwrap();
        (server, resp)
    }

    #[tokio::test]
    async fn reads_short_body_entirely() {
        let (_server, resp) = response_with_body(b"bad gateway".to_vec()).await;
        let body = read_body_prefix(resp, 4096, Duration::from_secs(5)).await;
        assert_eq!(body, b"bad gateway");
    }

    #[tokio::test]
    async fn truncates_body_longer_than_limit() {
        let (_server, resp) = response_with_body(vec![b'x'; 10_000]).await;
        let body = read_body_prefix(resp, 4096, Duration::from_secs(5)).await;
        assert_eq!(body.len(), 4096);
    }

    #[tokio::test]
    async fn empty_body_is_empty() {
        let (_server, resp) = response_with_body(Vec::new()).await;
        let body = read_body_prefix(resp, 4096, Duration::from_secs(5)).await;
        assert!(body.is_empty());
    }
}
