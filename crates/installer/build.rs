//! Embeds the payload — `vpnd`, `vpnctl` and the third-party notices of the programs
//! (`THIRD-PARTY-NOTICES.txt`, `scripts/third_party_notices.py`) — when `VPN_INSTALLER_PAYLOAD` names
//! a directory that holds them (scripts/package.sh does). Without it the installer is built empty
//! and takes the programs from `--payload <dir>`.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=VPN_INSTALLER_PAYLOAD");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let payload = std::env::var_os("VPN_INSTALLER_PAYLOAD").map(PathBuf::from);
    for name in ["vpnd", "vpnctl", "THIRD-PARTY-NOTICES.txt"] {
        let dest = out.join(name);
        match &payload {
            Some(dir) => {
                let src = dir.join(name);
                println!("cargo:rerun-if-changed={}", src.display());
                std::fs::copy(&src, &dest)
                    .unwrap_or_else(|e| panic!("payload {}: {e}", src.display()));
            }
            None => std::fs::write(&dest, b"").expect("write the empty payload"),
        }
    }
}
