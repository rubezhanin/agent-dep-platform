//! 2.10.0 (D1, audit): `agency health`
//! subcommand. Probes a running
//! `agency-server` via `GET /v1/health`.
//!
//! Designed for `docker-compose` /
//! `systemd` health checks. The pre-fix
//! `docker-compose.yml` used
//! `test: ["CMD", "agency-server", "--help"]`
//! which always exits 0 (the
//! `agency-server --help` codepath is
//! exit 0 by design). That meant a
//! crashed server still reported
//! "healthy" to Docker.
//!
//! `agency health --url <url>` POSTs a
//! GET to the URL with a configurable
//! timeout. Exit 0 iff the server
//! responds 200 with `{"status": "ok"}`.

use std::time::Duration;

/// Run the health probe. Returns
/// `Ok(())` if the server reports
/// `{"status": "ok"}`. On any failure
/// (timeout, non-2xx, missing `status`
/// field, wrong value) returns an
/// `Err(i32)` carrying the exit code
/// the caller should pass to
/// `std::process::exit`. The 1.0.0
/// process-exit contract is
/// "non-zero = unhealthy"; the exact
/// code is opaque to docker-compose
/// (`interval: 30s` retries on any
/// non-zero).
pub async fn run(url: String, timeout_secs: u64) -> Result<(), i32> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| {
            eprintln!("agency health: failed to build HTTP client: {e}");
            1
        })?;
    let resp = client.get(&url).send().await.map_err(|e| {
        eprintln!("agency health: GET {url} failed: {e}");
        1
    })?;
    let status = resp.status();
    if !status.is_success() {
        eprintln!(
            "agency health: GET {url} returned {} (not 2xx)",
            status.as_u16()
        );
        return Err(1);
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        eprintln!("agency health: failed to parse JSON body: {e}");
        1
    })?;
    match body.get("status").and_then(|s| s.as_str()) {
        Some("ok") => {
            println!("agency health: ok ({url})");
            Ok(())
        }
        Some(other) => {
            eprintln!("agency health: server returned status={other:?}, expected \"ok\"");
            Err(1)
        }
        None => {
            eprintln!("agency health: server JSON has no `status` field");
            Err(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 2.10.0 (D1, audit) unit test:
    /// spin up a tiny TCP server
    /// that responds to
    /// `GET /v1/health` with
    /// `{"status":"ok"}` and
    /// verify `agency health`
    /// returns `Ok(())`. Uses
    /// a real loopback HTTP
    /// server (no reqwest
    /// mocking) so the wiring
    /// through `reqwest` →
    /// `axum`-style JSON body
    /// is end-to-end.
    #[tokio::test]
    async fn health_probe_succeeds_on_200_ok() {
        // Bind a real TCP listener
        // on a random port and
        // serve one canned HTTP
        // response.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = s.read(&mut buf).await;
                // Minimal HTTP/1.1
                // response. The
                // `Content-Length` is
                // the byte length of
                // the body.
                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        let url = format!("http://{addr}/v1/health");
        let result = run(url, 3).await;
        assert!(
            result.is_ok(),
            "expected Ok(()) on 200 + status:ok, got {result:?}"
        );
        let _ = server.await;
    }

    /// 2.10.0 (D1): a server
    /// returning 500 must
    /// fail the probe.
    #[tokio::test]
    async fn health_probe_fails_on_500() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = s.read(&mut buf).await;
                let body = "internal error";
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        let url = format!("http://{addr}/v1/health");
        let result = run(url, 3).await;
        assert!(result.is_err(), "expected Err on 500, got {result:?}");
        let _ = server.await;
    }

    /// 2.10.0 (D1): a server
    /// returning 200 with a
    /// body that lacks
    /// `{"status":"ok"}` must
    /// fail the probe (the
    /// upstream audit B3 used
    /// this exact check for the
    /// secret reveal — same
    /// shape).
    #[tokio::test]
    async fn health_probe_fails_on_wrong_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = s.read(&mut buf).await;
                let body = r#"{"status":"degraded"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        let url = format!("http://{addr}/v1/health");
        let result = run(url, 3).await;
        assert!(
            result.is_err(),
            "expected Err on wrong status, got {result:?}"
        );
        let _ = server.await;
    }

    /// 2.10.0 (D1): a closed
    /// port must fail the probe
    /// (the docker-compose
    /// restart-on-failure case).
    #[tokio::test]
    async fn health_probe_fails_on_connection_refused() {
        // Pick a port that is
        // almost certainly not
        // bound (1 is privileged
        // and would be refused
        // immediately).
        let url = "http://127.0.0.1:1/v1/health".to_string();
        let result = run(url, 1).await;
        assert!(result.is_err(), "expected Err on connection refused");
    }
}
