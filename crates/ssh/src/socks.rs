//! SOCKS5 CONNECT through a VPN Manager Gateway.
//!
//! The destination name is handed to the Gateway
//! unresolved (resolved inside the tunnel). Any refusal is an error with a user-facing reason:
//! callers fail instead of falling back to a direct connection.

#![expect(
    unsafe_code,
    reason = "getuid for the ownership check of the Gateway key file"
)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vpn_domain::{Text, tr};

/// Why a connection through a Gateway failed. [`SocksError::text`] is the reason a person
/// reads; `Display` is its English.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    NotOurs,
    Gateway(SocketAddr, std::io::Error),
    Refused(u8),
    /// The Gateway's answer is not SOCKS5 (what is wrong with it).
    Protocol(Text),
    NameTooLong,
    Io(#[from] std::io::Error),
}

impl SocksError {
    /// The reason, in the three languages (the operating system's words as they are).
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::NotOurs => tr!(
                "The Gateway is not one of this VPN Manager (it cannot prove itself); stopped so as not to leave through another exit",
                "代理埠不是這個 VPN Manager 的代理埠（無法證明身分），為避免改走其他出口已中止",
                "このゲートウェイはこの VPN Manager のものではありません（身元を証明できません）。別の出口を経由しないよう中止しました"
            ),
            Self::Gateway(gateway, e) => tr!(
                "Cannot reach the Gateway {gateway}: {e} (the Gateway may be disabled, or VPN Manager is not running)",
                "無法連到代理埠 {gateway}：{e}（代理埠可能已停用，或 VPN Manager 沒有執行）",
                "ゲートウェイ {gateway} に接続できません：{e}（ゲートウェイが無効になっているか、VPN Manager が実行されていない可能性があります）"
            ),
            Self::Refused(code) => refusal(*code),
            Self::Protocol(what) => tr!(
                "The Gateway's answer does not follow SOCKS5: {what}",
                "代理埠的回應不符合 SOCKS5：{what}",
                "ゲートウェイの応答が SOCKS5 に従っていません：{what}";
                what = what.clone()
            ),
            Self::NameTooLong => tr!(
                "The host name is too long",
                "主機名稱過長",
                "ホスト名が長すぎます"
            ),
            Self::Io(e) => tr!(
                "The connection to the Gateway was broken: {e}",
                "與代理埠的連線中斷：{e}",
                "ゲートウェイとの接続が切断されました：{e}"
            ),
        }
    }
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

/// Read the installation's Gateway key: 32 bytes, owned by this user, unreadable by others.
///
/// # Errors
///
/// A user-facing reason when the file cannot be opened (a symlink is refused) or read, or its
/// owner, permissions or length are wrong.
pub fn read_key_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<[u8; 32]>, Text> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let shown = path.display();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            tr!(
                "Cannot read the Gateway key file {shown}: {e}",
                "無法讀取代理埠金鑰檔 {shown}：{e}",
                "ゲートウェイの鍵ファイル {shown} を読み取れません：{e}"
            )
        })?;
    let m = f.metadata().map_err(|e| Text::verbatim(e.to_string()))?;
    // SAFETY: getuid has no preconditions.
    if m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0 || m.len() != 32 {
        return Err(tr!(
            "The owner, permissions or length of the Gateway key file {shown} are not right",
            "代理埠金鑰檔 {shown} 的擁有者、權限或長度不正確",
            "ゲートウェイの鍵ファイル {shown} の所有者、権限、または長さが正しくありません"
        ));
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    f.read_exact(key.as_mut())
        .map_err(|e| Text::verbatim(e.to_string()))?;
    Ok(key)
}

/// What a SOCKS5 reply code means for the user.
fn refusal(code: u8) -> Text {
    match code {
        0x02 => tr!(
            "The Gateway refused the connection: the VPN connection is not ready, or the security profile does not allow this destination (it never falls back to the ordinary network)",
            "代理埠拒絕連線：VPN 連線未就緒，或安全設定不允許這個目的地（不會改走一般網路）",
            "ゲートウェイが接続を拒否しました：VPN 接続の準備ができていないか、セキュリティ設定がこの宛先を許可していません（通常のネットワークに切り替えることはありません）"
        ),
        0x03 => tr!(
            "The destination network cannot be reached through the VPN",
            "經 VPN 無法到達目的網路",
            "VPN 経由で宛先のネットワークに到達できません"
        ),
        0x04 => tr!(
            "The destination host cannot be reached through the VPN",
            "經 VPN 無法到達目的主機",
            "VPN 経由で宛先のホストに到達できません"
        ),
        0x05 => tr!(
            "The destination host refused the connection",
            "目的主機拒絕連線",
            "宛先のホストが接続を拒否しました"
        ),
        0x06 => tr!(
            "The connection through the VPN timed out",
            "經 VPN 連線逾時",
            "VPN 経由の接続がタイムアウトしました"
        ),
        0x07 => tr!(
            "The Gateway does not support this command",
            "代理埠不支援這個指令",
            "ゲートウェイはこのコマンドに対応していません"
        ),
        0x08 => tr!(
            "The Gateway does not support this kind of address",
            "代理埠不支援這種位址",
            "ゲートウェイはこの種類のアドレスに対応していません"
        ),
        code => tr!(
            "The Gateway reported an error (SOCKS5 code {code})",
            "代理埠回報錯誤（SOCKS5 代碼 {code}）",
            "ゲートウェイがエラーを報告しました（SOCKS5 コード {code}）"
        ),
    }
}

/// The Gateway's first answer is not SOCKS version 5.
fn not_version_5() -> SocksError {
    SocksError::Protocol(tr!(
        "version is not 5",
        "版本不是 5",
        "バージョンが 5 ではありません"
    ))
}

/// The Gateway wants a login, where none is offered.
fn asks_authentication() -> SocksError {
    SocksError::Protocol(tr!(
        "the Gateway asks for authentication",
        "代理埠要求驗證",
        "ゲートウェイが認証を求めています"
    ))
}

/// The Gateway's reply to CONNECT is not SOCKS version 5.
fn reply_not_version_5() -> SocksError {
    SocksError::Protocol(tr!(
        "reply version is not 5",
        "回應版本不是 5",
        "応答のバージョンが 5 ではありません"
    ))
}

/// The reply's bound address is of a type SOCKS5 does not have.
fn unknown_address_type() -> SocksError {
    SocksError::Protocol(tr!(
        "unknown address type",
        "未知的位址類型",
        "不明なアドレスの種類"
    ))
}

/// What a connection through a Gateway carries. The Gateway counts its bytes as that kind of
/// traffic; nothing else about the connection depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carries {
    /// An SSH session (`vpnctl ssh-proxy`, the SSH host test): 「SSH 代理」.
    SshSession,
    /// VPN Manager's own SSH download: 「SSH 下載」.
    SshPull,
}

impl Carries {
    /// The private method listed after the offered one to say so (never selected).
    const fn mark(self) -> u8 {
        use vpn_ipc::identity::{GATEWAY_MARK_SSH_PULL, GATEWAY_MARK_SSH_SESSION};
        match self {
            Self::SshSession => GATEWAY_MARK_SSH_SESSION,
            Self::SshPull => GATEWAY_MARK_SSH_PULL,
        }
    }
}

/// Open a stream to `host:port` through the SOCKS5 Gateway at `gateway`.
///
/// With `key`, only the private method is offered and the Gateway must prove it belongs to this
/// installation. `carries` is listed as a private method the Gateway never selects (it only says
/// how to count the connection's bytes).
///
/// # Errors
///
/// [`SocksError::Gateway`] when the Gateway cannot be reached, [`SocksError::NotOurs`] when it
/// does not prove itself, [`SocksError::Refused`] with its reply code, and protocol, name
/// length or I/O errors.
pub async fn connect(
    gateway: SocketAddr,
    host: &str,
    port: u16,
    key: Option<&[u8; 32]>,
    carries: Carries,
) -> Result<TcpStream, SocksError> {
    use vpn_ipc::identity::{GATEWAY_AUTH_METHOD, gateway_proof};
    let mut s = TcpStream::connect(gateway)
        .await
        .map_err(|e| SocksError::Gateway(gateway, e))?;
    s.set_nodelay(true)?;
    let offered = if key.is_some() {
        GATEWAY_AUTH_METHOD
    } else {
        0x00
    };
    s.write_all(&[0x05, 0x02, offered, carries.mark()]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    if method[0] != 0x05 {
        return Err(not_version_5());
    }
    match key {
        Some(key) => {
            use rand::TryRng;
            if method[1] != GATEWAY_AUTH_METHOD {
                return Err(SocksError::NotOurs);
            }
            let mut nonce = [0u8; 32];
            rand::rngs::SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|e| SocksError::Io(std::io::Error::other(e)))?;
            s.write_all(&nonce).await?;
            let mut proof = [0u8; 32];
            s.read_exact(&mut proof).await?;
            if proof != gateway_proof(key, &nonce) {
                return Err(SocksError::NotOurs);
            }
        }
        None if method[1] != 0x00 => return Err(asks_authentication()),
        None => {}
    }
    let mut req = vec![0x05, 0x01, 0x00];
    match host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        Ok(IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let name = host.as_bytes();
            let len = u8::try_from(name.len()).map_err(|_too_long| SocksError::NameTooLong)?;
            req.push(0x03);
            req.push(len);
            req.extend_from_slice(name);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(reply_not_version_5());
    }
    if head[1] != 0x00 {
        return Err(SocksError::Refused(head[1]));
    }
    // Bound address: not used, but it must be consumed.
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => return Err(unknown_address_type()),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

/// Prove the path works: CONNECT through the Gateway and read the server's SSH banner (no
/// authentication is attempted). Returns the banner and the elapsed time.
///
/// # Errors
///
/// A user-facing reason when the connection fails, times out or the server sends no SSH
/// banner.
pub async fn ssh_banner(
    gateway: SocketAddr,
    host: &str,
    port: u16,
    key: Option<&[u8; 32]>,
    timeout: Duration,
) -> Result<(String, Duration), Text> {
    let started = Instant::now();
    let probe = async {
        let mut s = connect(gateway, host, port, key, Carries::SshSession)
            .await
            .map_err(|e| e.text())?;
        let mut buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        // RFC 4253: the identification line ends with CRLF, at most 255 bytes.
        while buf.len() < 255 {
            match s.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => buf.push(byte[0]),
                Err(e) => {
                    return Err(tr!(
                        "Broken off while reading the SSH identification string: {e}",
                        "讀取 SSH 識別字串時中斷：{e}",
                        "SSH 識別文字列の読み取り中に切断されました：{e}"
                    ));
                }
            }
        }
        let line = String::from_utf8_lossy(&buf)
            .trim_end_matches('\r')
            .to_string();
        if line.starts_with("SSH-") {
            Ok(line)
        } else if line.is_empty() {
            Err(tr!(
                "The destination host sent no SSH identification string",
                "目的主機沒有回應 SSH 識別字串",
                "宛先のホストが SSH 識別文字列を返しませんでした"
            ))
        } else {
            let said: String = line.chars().take(60).collect();
            Err(tr!(
                "The destination host did not answer with SSH: {said}",
                "目的主機回應的不是 SSH：{said}",
                "宛先のホストの応答が SSH ではありません：{said}"
            ))
        }
    };
    match tokio::time::timeout(timeout, probe).await {
        Ok(Ok(banner)) => Ok((banner, started.elapsed())),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            let secs = timeout.as_secs();
            Err(tr!(
                "Not completed within {secs} s (through the VPN)",
                "{secs} 秒內沒有完成（經 VPN）",
                "{secs} 秒以内に完了しませんでした（VPN 経由）"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use tokio::net::TcpListener;

    use super::*;

    use vpn_ipc::identity::GATEWAY_AUTH_METHOD;

    const KEY: [u8; 32] = [7; 32];

    /// Another program on the port (a plain SOCKS server, `ssh -D`) cannot prove itself, so
    /// the connection never leaves through someone else's exit.
    #[tokio::test]
    async fn a_foreign_socks_server_is_refused() {
        // It insists on no authentication.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut hello = [0u8; 4];
            s.read_exact(&mut hello).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
        });
        let e = connect(addr, "git.example", 22, Some(&KEY), Carries::SshSession)
            .await
            .err()
            .unwrap();
        assert_matches!(e, SocksError::NotOurs, "{e}");

        // It plays along but cannot compute the proof.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut hello = [0u8; 4];
            s.read_exact(&mut hello).await.unwrap();
            s.write_all(&[0x05, GATEWAY_AUTH_METHOD]).await.unwrap();
            let mut nonce = [0u8; 32];
            s.read_exact(&mut nonce).await.unwrap();
            s.write_all(&[0u8; 32]).await.unwrap();
        });
        let e = connect(addr, "git.example", 22, Some(&KEY), Carries::SshSession)
            .await
            .err()
            .unwrap();
        assert_matches!(e, SocksError::NotOurs, "{e}");
    }

    #[test]
    fn the_key_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.key");
        std::fs::write(&path, KEY).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key_file(&path).is_err(), "readable by others");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(*read_key_file(&path).unwrap(), KEY);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_key_file(&link).is_err(), "symlinks are not followed");
    }
}
