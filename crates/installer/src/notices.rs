//! The licences of what this installer carries: VPN Manager's own, and the notices of the
//! third-party software in `vpnd`, `vpnctl` and the installer itself, embedded at build time by
//! `scripts/package.sh` (`scripts/third_party_notices.py` writes them from the lock files).

use std::io::Write as _;

static THIRD_PARTY: &str = include_str!(concat!(env!("OUT_DIR"), "/THIRD-PARTY-NOTICES.txt"));

/// Prints the licences; false when this installer was built without the notices.
pub fn print() -> bool {
    if THIRD_PARTY.is_empty() {
        eprintln!(
            "vpn-installer：這個安裝程式沒有內含第三方授權聲明（不是 scripts/package.sh 打包的）。VPN Manager 以 MIT 或 Apache-2.0 授權，其中的 AirVPN 轉接器是 GPL-3.0-or-later；見原始碼的 LICENSE-MIT、LICENSE-APACHE、LICENSE-GPL-3.0 與 NOTICE"
        );
        return false;
    }
    // The reader may stop early (a pager, `head`): a closed pipe is not a failure.
    let _ = std::io::stdout().write_all(THIRD_PARTY.as_bytes());
    true
}
