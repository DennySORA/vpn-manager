//! The programs this installer puts in place — `vpnd` and `vpnctl` — embedded at build time by
//! scripts/package.sh, or read from `--payload <dir>` in development. Before anything installed
//! is touched, the payload is written to the staging area and the staged `vpnd` is asked what it
//! is: it must run on this machine, be a release build and carry the web UI.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use crate::fsx::{self, sha256_hex};

static EMBEDDED_VPND: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vpnd"));
static EMBEDDED_VPNCTL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vpnctl"));

pub struct Payload {
    vpnd: Cow<'static, [u8]>,
    vpnctl: Cow<'static, [u8]>,
}

/// A staged payload that passed its checks.
pub struct Staged {
    pub version: String,
    /// What the running programs report (`<version>+<first 16 hex of the vpnd SHA-256>`).
    pub build_id: String,
    pub vpnd_sha256: String,
    pub vpnctl_sha256: String,
    pub vpnd: PathBuf,
    pub vpnctl: PathBuf,
}

impl Payload {
    pub fn load(dir: Option<&Path>) -> anyhow::Result<Self> {
        match dir {
            Some(dir) => {
                let read = |name: &str| {
                    std::fs::read(dir.join(name))
                        .with_context(|| format!("讀取 {}", dir.join(name).display()))
                };
                Ok(Self {
                    vpnd: Cow::Owned(read("vpnd")?),
                    vpnctl: Cow::Owned(read("vpnctl")?),
                })
            }
            None if Self::embedded() => Ok(Self {
                vpnd: Cow::Borrowed(EMBEDDED_VPND),
                vpnctl: Cow::Borrowed(EMBEDDED_VPNCTL),
            }),
            None => bail!(
                "這個安裝程式沒有內含 VPN Manager：請用 scripts/package.sh 打包，或以 --payload <目錄> 指定含 vpnd 與 vpnctl 的目錄"
            ),
        }
    }

    pub fn vpnd_sha256(&self) -> String {
        sha256_hex(&self.vpnd)
    }

    pub fn embedded() -> bool {
        !EMBEDDED_VPND.is_empty() && !EMBEDDED_VPNCTL.is_empty()
    }

    /// Writes the programs into `staging` and checks them.
    pub fn stage(&self, staging: &Path) -> anyhow::Result<Staged> {
        let vpnd = staging.join("vpnd");
        let vpnctl = staging.join("vpnctl");
        fsx::write_atomic(&vpnd, &self.vpnd, 0o755)?;
        fsx::write_atomic(&vpnctl, &self.vpnctl, 0o755)?;
        let out = Command::new(&vpnd)
            .arg("build-info")
            .output()
            .with_context(|| format!("無法在這台機器上執行內含的 vpnd（{}）", vpnd.display()))?;
        if !out.status.success() {
            bail!(
                "內含的 vpnd 無法回報版本資訊（{}）：{}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let info: serde_json::Value =
            serde_json::from_slice(&out.stdout).context("內含的 vpnd 回報了無法解讀的版本資訊")?;
        let version = info["version"]
            .as_str()
            .context("版本資訊缺少 version")?
            .to_owned();
        if info["release"] != serde_json::Value::Bool(true) {
            bail!("內含的 vpnd 是 debug 版：請打包 release 版（scripts/package.sh）");
        }
        if info["web_assets"] != serde_json::Value::Bool(true) {
            bail!("內含的 vpnd 沒有網頁介面：請先建置前端再打包（scripts/package.sh）");
        }
        let vpnd_sha256 = sha256_hex(&self.vpnd);
        Ok(Staged {
            build_id: build_id(&version, &vpnd_sha256),
            version,
            vpnctl_sha256: sha256_hex(&self.vpnctl),
            vpnd_sha256,
            vpnd,
            vpnctl,
        })
    }
}

/// The identity `vpnd` reports for itself: its version and the start of its SHA-256 (the first 16
/// hex digits; all of a shorter text).
pub fn build_id(version: &str, vpnd_sha256: &str) -> String {
    format!("{version}+{}", vpnd_sha256.get(..16).unwrap_or(vpnd_sha256))
}
