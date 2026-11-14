//! Architecture §8: a worker reaches the host network in exactly two places, both on loopback —
//! a SOCKS5 UDP relay socket bound on its client's loopback address (`gateway/udp.rs`) and the
//! connection to a port forward's App (`forward/endpoint.rs`, only to a loopback address a
//! manager lease names). Everything else goes into the tunnel. Checked on the source, so a new
//! host socket cannot slip in unnoticed.

#![cfg(test)]

use std::path::Path;

/// Calls that open a host socket (or ask the host resolver). Adopting a descriptor the manager
/// handed over (Gateway listeners, the strict sandbox's sockets) opens nothing and is not listed.
const FORBIDDEN: &[&str] = &[
    "TcpStream::connect",
    "TcpSocket::",
    "UdpSocket::bind",
    "TcpListener::bind",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
    "getaddrinfo",
];

/// The only files that may: what each one is for.
const ALLOWED: &[(&str, &str)] = &[
    (
        "forward/endpoint.rs",
        "a forward's App, on a leased loopback address",
    ),
    (
        "gateway/udp.rs",
        "SOCKS5 UDP relay bound on the client's loopback address",
    ),
    (
        "testsupport.rs",
        "loopback connector of the testing feature",
    ),
];

fn scan(root: &Path, dir: &Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            scan(root, &path, hits);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("inside src")
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.iter().any(|(file, _)| *file == rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source file");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for f in FORBIDDEN {
                if code.contains(f) {
                    hits.push(format!("{rel}:{}: {f}", n + 1));
                }
            }
        }
    }
}

#[test]
fn the_worker_opens_host_sockets_only_where_allowed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (file, _) in ALLOWED {
        assert!(root.join(file).exists(), "allowed file {file} is gone");
    }
    let mut hits = Vec::new();
    scan(&root, &root, &mut hits);
    assert!(
        hits.is_empty(),
        "host sockets outside the allowed places:\n{}",
        hits.join("\n")
    );
}
