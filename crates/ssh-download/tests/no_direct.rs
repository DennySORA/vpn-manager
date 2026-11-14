//! Architecture §8: SSH download reaches a server only through a VPN Manager Gateway. The
//! component's one network call is the SOCKS5 CONNECT to its Gateway's loopback port
//! (`vpn_ssh::socks::connect` on `127.0.0.1`, in `session.rs`); SSH runs over that stream
//! (`russh::client::connect_stream`). Nothing else may open a socket or resolve a name — checked
//! on the source, so a direct path cannot slip in unnoticed.

use std::path::Path;

/// Calls that would reach the network (or the host resolver) directly.
const FORBIDDEN: &[&str] = &[
    "TcpStream::connect",
    "TcpSocket::",
    "UdpSocket::",
    "TcpListener::",
    "UnixStream::connect",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
    "getaddrinfo",
    // russh's helper that dials by itself (only `connect_stream` over the Gateway's stream).
    "client::connect(",
    "reqwest",
];

fn scan(dir: &Path, hits: &mut Vec<String>, socks: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            scan(&path, hits, socks);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source file");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for f in FORBIDDEN {
                if code.contains(f) {
                    hits.push(format!("{}:{}: {f}", path.display(), n + 1));
                }
            }
            if code.contains("socks::connect(") {
                socks.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    }
}

#[test]
fn the_only_way_out_is_the_gateways_loopback_port() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let (mut hits, mut socks) = (Vec::new(), Vec::new());
    scan(&src, &mut hits, &mut socks);
    assert!(
        hits.is_empty(),
        "direct network access found:\n{}",
        hits.join("\n")
    );
    assert_eq!(socks.len(), 1, "one SOCKS5 call, in session.rs: {socks:?}");
    assert!(socks[0].contains("session.rs"), "{socks:?}");
    let session = std::fs::read_to_string(src.join("session.rs")).unwrap();
    assert!(
        session.contains("SocketAddr::from((Ipv4Addr::LOCALHOST, gateway.port))"),
        "the Gateway is dialled on loopback"
    );
    assert!(
        session.contains("russh::client::connect_stream("),
        "SSH runs over the Gateway's stream"
    );
}
