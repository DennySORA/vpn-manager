//! The installer's own record of what it installed (`installer/state.json` under the root,
//! 0600): the build, its hashes and the options an upgrade keeps. No secret is in it.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::fsx;

pub const SCHEMA: u32 = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct Record {
    pub schema: u32,
    pub version: String,
    pub build_id: String,
    pub vpnd_sha256: String,
    pub vpnctl_sha256: String,
    /// Port of the web UI and API.
    pub port: u16,
    /// Address the web UI listens on when it is not `127.0.0.1` (`--listen-address`).
    #[serde(default)]
    pub listen_address: Option<String>,
    /// Networks other hosts may use the web UI from (`--allow-client`).
    #[serde(default)]
    pub allow_clients: Vec<String>,
    pub ssh_dir: Option<PathBuf>,
    pub supervisor: String,
    pub services: Vec<String>,
    pub installed_at: String,
    pub updated_at: String,
    /// Linux: this installer turned on lingering for the user (so the services run without a
    /// login session).
    #[serde(default)]
    pub linger_enabled: bool,
}

impl Record {
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                    format!("安裝紀錄 {} 無法解讀", path.display())
                })?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("讀取 {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        fsx::write_atomic(path, &bytes, 0o600).with_context(|| format!("寫入 {}", path.display()))
    }
}

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// A name for a backup directory that sorts by time: `20261027T072301Z`.
pub fn stamp() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}
