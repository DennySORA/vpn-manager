//! Build identity of the running executable.
//!
//! `build_id = <crate version>+<sha256(executable)[..16]>`. Every process computes it from the
//! file it was actually started from, so a binary replaced on disk between a manager start and a
//! worker spawn is detected in the first IPC message instead of failing later with an
//! incompatible protocol.

use std::io::Read;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

static BUILD_ID: OnceLock<String> = OnceLock::new();
static EXE_DIGEST: OnceLock<Result<(String, u64), String>> = OnceLock::new();

/// Git revision the binary was built from (display only).
pub const GIT_REV: &str = env!("VPN_GIT_REV");

/// Crate version (display only).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The executable's build id (computed once).
pub fn build_id() -> &'static str {
    BUILD_ID.get_or_init(|| {
        let digest = executable_sha256().map_or_else(|_| "unknown".into(), |(d, _)| d.to_string());
        format!("{VERSION}+{}", &digest[..digest.len().min(16)])
    })
}

/// SHA-256 (hex) and size of the running executable, computed once at first use (which `vpnd`
/// does at start, before anything could replace the file).
///
/// # Errors
///
/// The message of the I/O error that kept the executable from being read on first use.
pub fn executable_sha256() -> Result<(&'static str, u64), &'static str> {
    match EXE_DIGEST.get_or_init(|| executable_digest_now().map_err(|e| e.to_string())) {
        Ok((digest, size)) => Ok((digest.as_str(), *size)),
        Err(e) => Err(e.as_str()),
    }
}

fn executable_digest_now() -> std::io::Result<(String, u64)> {
    // On Linux /proc/self/exe stays valid even if the file was replaced or deleted.
    #[cfg(target_os = "linux")]
    let path = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let path = std::env::current_exe()?;
    file_sha256(&path)
}

/// SHA-256 (hex) and size of a file.
///
/// # Errors
///
/// Any I/O error opening or reading `path`.
pub fn file_sha256(path: &std::path::Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

/// Private SOCKS5 method (0x80) by which a Gateway proves it belongs to this installation.
///
/// The client sends a 32-byte nonce and checks the answer. A program that merely holds the same port
/// (another SOCKS server, `ssh -D`) cannot answer, so `vpnctl` fails instead of leaving through
/// some other path.
pub const GATEWAY_AUTH_METHOD: u8 = 0x80;

/// Private SOCKS5 methods that say what a connection carries (never selected).
///
/// A VPN Manager client lists one after [`GATEWAY_AUTH_METHOD`], so the Gateway counts the
/// connection's bytes as that kind of traffic: an SSH session (`vpnctl ssh-proxy`, the SSH host
/// test: 「SSH 代理」) or VPN Manager's own SSH download (「SSH 下載」). A Gateway that does not
/// know them (an earlier release) ignores them and classifies by the destination port alone.
/// Only accounting depends on them: the connection is handled the same either way.
pub const GATEWAY_MARK_SSH_SESSION: u8 = 0x81;
pub const GATEWAY_MARK_SSH_PULL: u8 = 0x82;

/// HMAC-SHA256(installation gateway key, label ‖ nonce).
#[must_use]
pub fn gateway_proof(key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; 32];
    };
    mac.update(b"vpn-manager-gateway-v1");
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}
