//! Whether the installed programs actually serve: `GET /v1/system/status` of the controller on
//! loopback must answer, report the manager connected, and come from the expected build.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};

pub struct Status {
    pub manager_connected: bool,
    pub build_id: String,
    pub version: String,
}

pub fn probe(port: u16) -> anyhow::Result<Status> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        s,
        "GET /v1/system/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    s.take(1 << 20).read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").context("回應不完整")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200") {
        bail!("{status}");
    }
    let v: serde_json::Value = serde_json::from_str(body)?;
    Ok(Status {
        manager_connected: v["manager_connected"] == serde_json::Value::Bool(true),
        build_id: v["build_id"].as_str().unwrap_or_default().to_owned(),
        version: v["version"].as_str().unwrap_or_default().to_owned(),
    })
}

/// Waits until the web UI answers with the manager connected — from `build_id` when given.
pub fn wait_ready(port: u16, build_id: Option<&str>, within: Duration) -> anyhow::Result<Status> {
    let end = Instant::now() + within;
    loop {
        let last = match probe(port) {
            Ok(s) if s.manager_connected && build_id.is_none_or(|b| s.build_id == b) => {
                return Ok(s);
            }
            Ok(s) if build_id.is_some_and(|b| s.build_id != b) => format!(
                "回應的是 build {}，不是 {}",
                s.build_id,
                build_id.unwrap_or_default()
            ),
            Ok(_) => "網頁介面有回應，但 manager 還沒連上".into(),
            Err(e) => format!("網頁介面沒有回應：{e:#}"),
        };
        if Instant::now() >= end {
            bail!("{} 秒內沒有就緒（{last}）", within.as_secs());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// `preferred` when nothing listens on it (at 127.0.0.1 and at `address`), otherwise the first
/// free port above it.
pub fn free_port(preferred: u16, address: std::net::IpAddr) -> Option<u16> {
    (preferred..=preferred.saturating_add(100)).find(|p| port_is_free(*p, address))
}

/// Whether the controller could listen on `port`: at 127.0.0.1, and at `address` too.
pub fn port_is_free(port: u16, address: std::net::IpAddr) -> bool {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).is_ok()
        && (address.is_loopback() || TcpListener::bind(SocketAddr::new(address, port)).is_ok())
}
