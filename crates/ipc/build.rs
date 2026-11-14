//! Embed the git revision for display purposes. Process identity checks use the runtime hash
//! of the executable instead (see `identity.rs`), which cannot go stale.

use std::path::Path;
use std::process::Command;

fn main() {
    let git = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "nogit".into(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );
    println!("cargo:rustc-env=VPN_GIT_REV={git}");
    // HEAD names the branch; a commit moves the branch's ref (or `packed-refs`), not HEAD, so
    // all three are watched or the revision stays at the one of the first build.
    let dot_git = Path::new("../../.git");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    if let Ok(head) = std::fs::read_to_string(dot_git.join("HEAD"))
        && let Some(branch) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=../../.git/{branch}");
    }
}
