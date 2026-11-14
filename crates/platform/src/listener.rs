//! Loopback listeners held by the manager across worker generations.
//!
//! The kernel completes TCP handshakes even when nobody calls `accept`, so a held-but-idle
//! listener would let clients hang and later be served stale. While no worker serves a Gateway,
//! the manager runs [`reject_loop`]: every connection gets an immediate, explicit refusal.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use vpn_domain::{Text, tr};

/// Bind `127.0.0.1:port` (never another address).
///
/// # Errors
///
/// Fails when the port cannot be bound or made non-blocking.
pub fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Why connections are being refused; shown to HTTP clients.
#[derive(Debug, Clone, Copy)]
pub enum RejectReason {
    Reconnecting,
    Stopped,
}

impl RejectReason {
    fn text(self) -> Text {
        match self {
            Self::Reconnecting => tr!(
                "The VPN Instance is reconnecting; the connection was refused (it never falls back to the ordinary network).",
                "VPN Instance 正在重新連線，連線已拒絕（不會改走一般網路）。",
                "VPN Instance が再接続中のため、接続を拒否しました（通常のネットワークに切り替えることはありません）。"
            ),
            Self::Stopped => tr!(
                "The VPN Instance has stopped; the connection was refused (it never falls back to the ordinary network).",
                "VPN Instance 已停止，連線已拒絕（不會改走一般網路）。",
                "VPN Instance が停止しているため、接続を拒否しました（通常のネットワークに切り替えることはありません）。"
            ),
        }
    }
}

/// Accept and refuse until `cancel` fires.
///
/// SOCKS5 clients get a method-selection reply followed by 0x02 "connection not allowed by ruleset"
/// (same as a worker with a closed gate); anything else gets an HTTP 503 with an explanation.
pub async fn reject_loop(listener: TcpListener, reason: RejectReason, cancel: CancellationToken) {
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "reject loop could not register listener");
            return;
        }
    };
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => break,
            a = listener.accept() => a,
        };
        let Ok((mut stream, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        tokio::spawn(async move {
            let mut first = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.peek(&mut first)).await;
            if matches!(read, Ok(Ok(1))) && first[0] == 0x05 {
                // Consume the greeting, pick "no auth", then fail the request.
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_ok() {
                    let mut methods = vec![0u8; greeting[1] as usize];
                    let _ = stream.read_exact(&mut methods).await;
                    let _ = stream.write_all(&[0x05, 0x00]).await;
                    let mut req = [0u8; 4];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut req))
                            .await;
                    let _ = stream
                        .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
            } else {
                // Whoever reads it, in each language: the request is not read.
                let text = reason.text();
                let body = format!("{}\n{}\n{}\n", text.en, text.zh_tw, text.ja);
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\nretry-after: 5\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
            // Lingering close: send FIN, then drain what the client already sent. Closing with
            // unread input makes the kernel send RST, and the client would lose our reply.
            let _ = stream.shutdown().await;
            let mut sink = [0u8; 4096];
            let drain = async {
                let mut total = 0usize;
                while let Ok(n) = stream.read(&mut sink).await {
                    if n == 0 || total > 64 * 1024 {
                        break;
                    }
                    total += n;
                }
            };
            let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_http_and_socks_immediately() {
        let l = bind_loopback(0).unwrap();
        let addr = l.local_addr().unwrap();
        let held = l.try_clone().unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(reject_loop(
            held,
            RejectReason::Reconnecting,
            cancel.clone(),
        ));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 503"));
        assert!(resp.contains("不會改走一般網路"));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x02, "not allowed by ruleset");
        cancel.cancel();
    }
}
