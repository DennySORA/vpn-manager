//! Architecture §7: the controller (and the provider adapters it runs) never opens a network
//! connection or resolves a name by itself. Every provider byte goes through a relay socket of
//! the manager. Checked on the source, so a new dial cannot slip in unnoticed.

#![cfg(test)]

use std::path::Path;

/// Calls that would reach the network (or the host resolver) directly.
const FORBIDDEN: &[&str] = &[
    "TcpStream::connect",
    "TcpSocket::",
    "UdpSocket::",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
    "getaddrinfo",
    "reqwest",
    "ureq",
];

fn scan(dir: &Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            scan(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("source file");
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for f in FORBIDDEN {
                    if code.contains(f) {
                        hits.push(format!("{}:{}: {f}", path.display(), n + 1));
                    }
                }
            }
        }
    }
}

#[test]
fn the_controller_and_the_adapters_never_dial() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    scan(&root.join("src"), &mut hits);
    scan(&root.join("../providers/src"), &mut hits);
    assert!(
        hits.is_empty(),
        "direct network access found:\n{}",
        hits.join("\n")
    );
}
