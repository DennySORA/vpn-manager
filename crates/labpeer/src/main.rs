//! `vpn-labpeer serve`: run a controlled `WireGuard` peer on loopback and write a client `.conf`
//! that can be imported into VPN Manager to see real traffic flow through the product.

// A `pub` item of a program that nothing uses is dead code all the same (off by default).
#![deny(dead_code_pub_in_binary)]
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "vpn-labpeer",
    about = "Controlled WireGuard test peer (loopback only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve until interrupted.
    Serve {
        /// UDP address to listen on (loopback only).
        #[arg(long, default_value = "127.0.0.1:51820")]
        listen: SocketAddr,
        /// Write the client configuration here (mode 0600). Printed to stdout when omitted.
        #[arg(long)]
        client_config: Option<PathBuf>,
        /// Keep the server and client keys in this file (mode 0600) so a restarted peer still
        /// matches a configuration imported earlier. Created when missing.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Loopback address of a test API: `POST /dial` connects *in* to the client's tunnel
        /// address through the lab tunnel (port-forward tests).
        #[arg(long)]
        api: Option<SocketAddr>,
        /// `PORT=ADDR`: relay TCP connections to `10.99.0.1:PORT` inside the tunnel to `ADDR` on
        /// this host's loopback (a real service, e.g. an unprivileged sshd). Repeatable.
        #[arg(long = "forward-tcp", value_name = "PORT=ADDR")]
        forward_tcp: Vec<String>,
    },
}

/// `PORT=ADDR` of `--forward-tcp`.
fn forward_of(spec: &str) -> anyhow::Result<(u16, SocketAddr)> {
    let (port, addr) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--forward-tcp takes PORT=ADDR, not {spec}"))?;
    Ok((port.parse()?, addr.parse()?))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().command {
        Command::Serve {
            listen,
            client_config,
            keys,
            api,
            forward_tcp,
        } => {
            let keys = match &keys {
                Some(path) => Some(load_or_create_keys(path)?),
                None => None,
            };
            let peer = vpn_labpeer::LabPeer::start_with(listen, 1, keys.as_ref()).await?;
            let conf = peer.clients[0].wg_quick_config(&peer);
            match client_config {
                Some(path) => {
                    write_private(&path, &conf)?;
                    report(&format!(
                        "client configuration written to {}",
                        path.display()
                    ));
                }
                None => print_config(&conf),
            }
            report(&format!(
                "labpeer listening on {} — in-tunnel services at 10.99.0.1 (echo 7, discard 9, source 19, ssh banner 22, http 80, dns 53)",
                peer.endpoint
            ));
            for spec in &forward_tcp {
                let (port, target) = forward_of(spec)?;
                let net = peer.netstack().ok_or_else(|| {
                    anyhow::anyhow!("this lab peer has no netstack to forward from")
                })?;
                vpn_labpeer::spawn_loopback_forward(&net, port, target)?;
                report(&format!(
                    "labpeer forwards 10.99.0.1:{port} in the tunnel to {target}"
                ));
            }
            if let (Some(addr), Some(net)) = (api, peer.netstack()) {
                anyhow::ensure!(addr.ip().is_loopback(), "the test API only binds loopback");
                let listener = tokio::net::TcpListener::bind(addr).await?;
                report(&format!("labpeer test API on http://{addr} (POST /dial)"));
                tokio::spawn(serve_api(listener, net, peer.clients[0].address_v4));
            }
            tokio::signal::ctrl_c().await?;
            peer.shutdown().await;
            Ok(())
        }
    }
}

/// The client configuration on stdout, when no file was given for it.
#[expect(
    clippy::print_stdout,
    reason = "without --client-config the configuration is the program's output, written only here"
)]
fn print_config(conf: &str) {
    println!("{conf}");
}

/// What the peer serves, for the person who started it, on stderr (stdout may carry the client
/// configuration).
#[expect(
    clippy::print_stderr,
    reason = "the peer's own messages go to stderr, and only through this function"
)]
fn report(line: &str) {
    eprintln!("{line}");
}

/// Two base64 lines: server private key, client private key.
fn load_or_create_keys(path: &PathBuf) -> anyhow::Result<vpn_labpeer::LabKeys> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    let decode = |line: Option<&str>| -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
        let bytes = zeroize::Zeroizing::new(B64.decode(line.unwrap_or_default().trim())?);
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        anyhow::ensure!(bytes.len() == 32, "labpeer key file holds an invalid key");
        key.copy_from_slice(&bytes);
        Ok(key)
    };
    if path.exists() {
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let mut lines = text.lines();
        return Ok(vpn_labpeer::LabKeys {
            server: decode(lines.next())?,
            client: decode(lines.next())?,
        });
    }
    let keys = vpn_labpeer::LabKeys::generate();
    let text = zeroize::Zeroizing::new(format!(
        "{}\n{}\n",
        B64.encode(*keys.server),
        B64.encode(*keys.client)
    ));
    write_private(path, &text)?;
    Ok(keys)
}

fn write_private(path: &PathBuf, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// `POST /dial` with a [`vpn_labpeer::DialRequest`]; answers a [`vpn_labpeer::DialReport`].
async fn serve_api(
    listener: tokio::net::TcpListener,
    net: vpn_tunnel::Netstack,
    client: std::net::Ipv4Addr,
) {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    while let Ok((stream, _)) = listener.accept().await {
        let net = net.clone();
        tokio::spawn(async move {
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let net = net.clone();
                    async move {
                        let (status, body) =
                            if req.method() == hyper::Method::POST && req.uri().path() == "/dial" {
                                match req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(http_body_util::Collected::to_bytes)
                                {
                                    Ok(bytes) => match serde_json::from_slice::<
                                        vpn_labpeer::DialRequest,
                                    >(&bytes)
                                    {
                                        Ok(d) => (
                                            200,
                                            serde_json::to_string(
                                                &vpn_labpeer::dial(&net, client, &d).await,
                                            )
                                            .unwrap_or_default(),
                                        ),
                                        Err(e) => (
                                            400,
                                            serde_json::json!({ "error": e.to_string() })
                                                .to_string(),
                                        ),
                                    },
                                    Err(_) => (400, "{}".into()),
                                }
                            } else {
                                (404, "{}".into())
                            };
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_default(),
                        )
                    }
                });
            #[expect(
                clippy::let_underscore_must_use,
                reason = "a client that resets or leaves ends only its own connection"
            )]
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}
