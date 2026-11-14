//! One SSH connection of a job: the component's only way to a server.
//!
//! A SOCKS5 CONNECT to the
//! job's Gateway on 127.0.0.1 (the host name goes to the Gateway unresolved and is resolved inside
//! its tunnel; the Gateway must prove it belongs to this installation), then SSH and SFTP over
//! that stream. A Gateway that is not there, refuses or cannot prove itself ends the attempt; there
//! is no other path to try. Nothing here opens a socket to anywhere but that loopback port.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use russh::MethodKind;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh_sftp::client::RawSftpSession;
use russh_sftp::protocol::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use vpn_domain::{Text, tr};
use vpn_ssh::socks::{self, Carries, SocksError};
use vpn_sync::Mutex;
use zeroize::Zeroizing;

/// A read asks for at most this much (servers cap theirs; OpenSSH at 255 KiB).
pub const READ_CHUNK: u32 = 128 * 1024;
/// SSH channel window: what the server may send ahead of what was read. Twice what one file
/// keeps in flight at most (16 MiB, see `pipeline::Pipeline`), so the window is never what holds
/// a file back.
const WINDOW: u32 = 32 * 1024 * 1024;

/// The server a job logs in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
}

impl Target {
    /// `host:port`, the scope of a trusted host key.
    #[must_use]
    pub fn label(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// How the job logs in.
#[derive(Clone, Default)]
pub struct Credentials {
    pub key: Option<Arc<PrivateKey>>,
    pub password: Option<Arc<Zeroizing<String>>>,
}

/// The Gateway to go through: its loopback port and the installation key it proves itself with.
#[derive(Clone)]
pub struct Gateway {
    pub port: u16,
    pub key: Arc<Zeroizing<[u8; 32]>>,
}

/// What the job decided about the key a server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The recorded key, or the first one (now recorded).
    Trusted,
    /// Not the recorded key: the connection is refused before anything is sent to the server.
    Changed { offered: String },
    /// The decision could not be recorded (the Store refused): refused, to be tried again.
    Unavailable(Text),
}

/// Decides about a server's host key (trust on first use, kept by the job).
pub trait HostKeys: Send + Sync + 'static {
    fn check<'a>(&'a self, key: &'a PublicKey) -> BoxFuture<'a, HostKeyVerdict>;
}

/// Why a connection could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The Gateway did not carry it: not listening, refused (its connection is not ready, or the
    /// security profile forbids the destination), or not ours. The job waits for the VPN.
    Vpn { code: &'static str, reason: Text },
    /// Through the VPN the server did not answer, or the SSH exchange failed: tried again later.
    Transient { code: &'static str, reason: Text },
    /// The server presented another key than the recorded one.
    HostKeyChanged { offered: String },
    /// The server refused every way to log in the job has.
    AuthRejected(Text),
}

fn transient(code: &'static str, reason: impl Into<Text>) -> OpenError {
    OpenError::Transient {
        code,
        reason: reason.into(),
    }
}

impl OpenError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Vpn { code, .. } | Self::Transient { code, .. } => code,
            Self::HostKeyChanged { .. } => "HOST_KEY_CHANGED",
            Self::AuthRejected(_) => "AUTH_REJECTED",
        }
    }

    #[must_use]
    pub fn reason(&self) -> Text {
        match self {
            Self::Vpn { reason, .. } | Self::Transient { reason, .. } => reason.clone(),
            Self::HostKeyChanged { offered } => tr!(
                "The server's host key is not the recorded one (it now offers {offered}). The server may have been reinstalled, or someone may be intercepting the connection; the job has stopped, and the new key can be trusted only once its fingerprint is confirmed",
                "伺服器的主機金鑰和記錄的不同（現在提供 {offered}）。可能是伺服器重新安裝，也可能是有人攔截連線；工作已停止，確認指紋正確後才能信任新的金鑰",
                "サーバーのホスト鍵が記録したものと異なります（現在の提示：{offered}）。サーバーが再インストールされたか、誰かが接続を傍受している可能性があります。ジョブは停止しました。フィンガープリントが正しいことを確認してから新しい鍵を信頼してください"
            ),
            Self::AuthRejected(why) => why.clone(),
        }
    }
}

/// A SOCKS5 refusal or failure as the job sees it.
fn socks_error(e: &SocksError) -> OpenError {
    match e {
        SocksError::Gateway(..) => OpenError::Vpn {
            code: "GATEWAY_UNREACHABLE",
            reason: tr!(
                "{why}; it never falls back to the ordinary network",
                "{why}；不會改走一般網路",
                "{why}。通常のネットワークには切り替わりません";
                why = e.text()
            ),
        },
        SocksError::NotOurs => OpenError::Vpn {
            code: "GATEWAY_NOT_OURS",
            reason: e.text(),
        },
        // 0x02: the gate is closed or the security profile refuses the destination.
        SocksError::Refused(0x02) => OpenError::Vpn {
            code: "GATEWAY_REFUSED",
            reason: e.text(),
        },
        SocksError::Refused(_) => transient("SERVER_UNREACHABLE", e.text()),
        SocksError::Protocol(_) | SocksError::NameTooLong | SocksError::Io(_) => {
            transient("GATEWAY_FAILED", e.text())
        }
    }
}

/// `items` one after another, with each language's separator ("A, B", "A、B").
fn list(items: &[Text]) -> Text {
    tr!(", ", "、", "、").map(|language, separator| {
        items
            .iter()
            .map(|item| item.get(language))
            .collect::<Vec<_>>()
            .join(separator)
    })
}

/// The russh client side: only the host key decision.
struct Client {
    host_keys: Arc<dyn HostKeys>,
    verdict: Arc<Mutex<Option<HostKeyVerdict>>>,
}

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            // A certificate's own key is what this job learns to trust.
            PublicKeyOrCertificate::Certificate(c) => PublicKey::new(c.public_key().clone(), ""),
        };
        let verdict = self.host_keys.check(&key).await;
        let ok = verdict == HostKeyVerdict::Trusted;
        *self.verdict.lock() = Some(verdict);
        Ok(ok)
    }
}

/// An open, logged-in connection with its SFTP session.
pub struct Session {
    ssh: russh::client::Handle<Client>,
    pub sftp: Arc<RawSftpSession>,
    /// The largest read this server serves.
    pub read_len: u32,
}

impl Session {
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.ssh.is_closed()
    }

    /// End the connection politely (best effort).
    pub async fn close(self) {
        let _ = self.sftp.close_session();
        let _ = self
            .ssh
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
    }
}

/// A key's fingerprint in OpenSSH form (`SHA256:…`).
#[must_use]
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

async fn login(
    ssh: &mut russh::client::Handle<Client>,
    target: &Target,
    creds: &Credentials,
) -> Result<(), OpenError> {
    let failed = |e: russh::Error| login_broke_off(&e);
    let mut tried: Vec<MethodKind> = Vec::new();
    let mut methods: Option<Vec<MethodKind>> = None;
    if let Some(key) = &creds.key {
        match ssh
            .authenticate_publickey(
                target.user.clone(),
                // No hash to choose: RSA keys are refused when the job's key is loaded.
                PrivateKeyWithHashAlg::new(key.clone(), None),
            )
            .await
            .map_err(failed)?
        {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                tried.push(MethodKind::PublicKey);
                methods = Some(remaining_methods.to_vec());
            }
        }
    }
    if let Some(password) = &creds.password {
        let allows = |m: MethodKind| methods.as_ref().is_none_or(|v| v.contains(&m));
        if allows(MethodKind::Password) {
            match ssh
                .authenticate_password(target.user.clone(), password.as_str())
                .await
                .map_err(failed)?
            {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure {
                    remaining_methods, ..
                } => {
                    tried.push(MethodKind::Password);
                    methods = Some(remaining_methods.to_vec());
                }
            }
        }
        // Many servers take a password only as a keyboard-interactive answer.
        if methods
            .as_ref()
            .is_some_and(|v| v.contains(&MethodKind::KeyboardInteractive))
        {
            let mut reply = ssh
                .authenticate_keyboard_interactive_start(target.user.clone(), None::<String>)
                .await
                .map_err(failed)?;
            for _ in 0..4 {
                match reply {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => break,
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        // One hidden prompt is the password; an empty round is answered empty.
                        let answers = match prompts.as_slice() {
                            [] => Vec::new(),
                            [p] if !p.echo => vec![password.to_string()],
                            _ => break,
                        };
                        reply = ssh
                            .authenticate_keyboard_interactive_respond(answers)
                            .await
                            .map_err(failed)?;
                    }
                }
            }
            tried.push(MethodKind::KeyboardInteractive);
        }
    }
    Err(login_refused(&tried))
}

/// The connection broke off during the login.
fn login_broke_off(e: &russh::Error) -> OpenError {
    transient(
        "SSH_FAILED",
        tr!(
            "The SSH connection broke off while logging in: {e}",
            "登入時 SSH 連線中斷：{e}",
            "ログイン中に SSH 接続が切断されました：{e}"
        ),
    )
}

/// The server refused the login after the methods `tried` (none: it takes none the job has).
fn login_refused(tried: &[MethodKind]) -> OpenError {
    let tried = if tried.is_empty() {
        tr!(
            "The server accepts none of the login methods this job has",
            "伺服器不接受這個工作設定的任何登入方式",
            "サーバーはこのジョブに設定したどのログイン方法も受け付けません"
        )
    } else {
        let names: Vec<Text> = tried
            .iter()
            .map(|m| match m {
                MethodKind::PublicKey => tr!("key", "金鑰", "鍵"),
                MethodKind::Password => tr!("password", "密碼", "パスワード"),
                MethodKind::KeyboardInteractive => tr!(
                    "keyboard-interactive",
                    "鍵盤互動",
                    "キーボードインタラクティブ"
                ),
                other => Text::verbatim(<&str>::from(other)),
            })
            .collect();
        tr!(
            "The server refused the login (tried: {tried})",
            "伺服器拒絕登入（試過：{tried}）",
            "サーバーがログインを拒否しました（試した方法：{tried}）";
            tried = list(&names)
        )
    };
    OpenError::AuthRejected(tr!(
        "{tried}; check the user name, key or password, then press “Retry”",
        "{tried}；請確認使用者名稱、金鑰或密碼後按「重試」",
        "{tried}。ユーザー名、鍵、またはパスワードを確認してから「再試行」を押してください";
        tried = tried
    ))
}

/// A stage of opening a connection, as a timeout names it.
#[derive(Clone, Copy)]
enum Stage {
    Gateway,
    Handshake,
    Login,
    Sftp,
}

impl Stage {
    /// The stage did not complete within `secs`.
    fn timed_out(self, secs: u64) -> OpenError {
        let what = match self {
            Self::Gateway => tr!(
                "Connecting through the Gateway",
                "經代理埠連線",
                "ゲートウェイ経由の接続"
            ),
            Self::Handshake => tr!("The SSH handshake", "SSH 交握", "SSH ハンドシェイク"),
            Self::Login => tr!("The login", "登入", "ログイン"),
            Self::Sftp => tr!("Starting SFTP", "SFTP 啟動", "SFTP の開始"),
        };
        transient(
            "TIMEOUT",
            tr!(
                "{what} did not complete within {secs} s (through the VPN)",
                "{what}在 {secs} 秒內沒有完成（經 VPN）",
                "{what}が {secs} 秒以内に完了しませんでした（VPN 経由）";
                what = what
            ),
        )
    }
}

/// SFTP could not start: no session channel.
fn no_channel(e: &russh::Error) -> OpenError {
    transient(
        "SFTP_FAILED",
        tr!(
            "Cannot open an SSH channel: {e}",
            "無法開啟 SSH 通道：{e}",
            "SSH チャネルを開けません：{e}"
        ),
    )
}

/// SFTP could not start: the server has no SFTP subsystem.
fn no_sftp(e: &russh::Error) -> OpenError {
    transient(
        "SFTP_FAILED",
        tr!(
            "The server does not offer SFTP: {e}",
            "伺服器不提供 SFTP：{e}",
            "サーバーが SFTP を提供していません：{e}"
        ),
    )
}

/// SFTP could not start: its version exchange failed.
fn sftp_init_failed(e: &russh_sftp::client::error::Error) -> OpenError {
    transient(
        "SFTP_FAILED",
        tr!(
            "SFTP initialization failed: {e}",
            "SFTP 初始化失敗：{e}",
            "SFTP の初期化に失敗しました：{e}"
        ),
    )
}

/// Why the SSH handshake failed, for the user. A server with RSA host keys only is named as
/// such: RSA is not built in.
fn handshake_failure(e: &russh::Error) -> Text {
    match e {
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => tr!(
            "The SSH handshake failed: the server has no host key this version supports (ed25519 and ECDSA are supported, RSA is not)",
            "SSH 交握失敗：伺服器沒有這個版本支援的主機金鑰（支援 ed25519 與 ECDSA，不支援 RSA）",
            "SSH ハンドシェイクに失敗しました：サーバーに、このバージョンが対応するホスト鍵がありません（ed25519 と ECDSA に対応し、RSA には対応していません）"
        ),
        e => tr!(
            "The SSH handshake failed: {e}",
            "SSH 交握失敗：{e}",
            "SSH ハンドシェイクに失敗しました：{e}"
        ),
    }
}

/// Open a connection to `target` through `gateway`, log in and start SFTP. `timeout` bounds each
/// stage (the Gateway's CONNECT inside the tunnel, the SSH exchange, the login, SFTP).
///
/// `carried` is called once the Gateway accepted the connection, with its stream, and returns what SSH runs
/// over: that stream itself, wrapped (to count its bytes) but never replaced.
///
/// # Errors
///
/// [`OpenError::Vpn`] when the Gateway is unreachable, not ours or refuses the destination,
/// [`OpenError::HostKeyChanged`] when the server's host key differs from the recorded one,
/// [`OpenError::AuthRejected`] when the login is refused, and [`OpenError::Transient`] for a
/// timeout or another failure of the SSH exchange or SFTP.
pub async fn open<S>(
    gateway: &Gateway,
    target: &Target,
    creds: &Credentials,
    host_keys: Arc<dyn HostKeys>,
    timeout: Duration,
    // The Gateway has accepted the connection: the VPN carries it from here on.
    carried: impl FnOnce(TcpStream) -> S,
) -> Result<Session, OpenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let within = |stage: Stage| move |_| stage.timed_out(timeout.as_secs());
    // The only connection this component ever opens: to its Gateway on loopback.
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, gateway.port));
    let key = Some(&**gateway.key);
    let stream = tokio::time::timeout(
        timeout,
        // The Gateway counts these bytes as SSH 下載, apart from SSH sessions.
        socks::connect(at, &target.host, target.port, key, Carries::SshPull),
    )
    .await
    .map_err(within(Stage::Gateway))?
    .map_err(|e| socks_error(&e))?;
    let stream = carried(stream);

    let config = Arc::new(russh::client::Config {
        // Silence for this long ends the connection; keepalives keep an idle one alive.
        inactivity_timeout: Some(Duration::from_secs(300)),
        keepalive_interval: Some(Duration::from_secs(20)),
        keepalive_max: 3,
        window_size: WINDOW,
        nodelay: true,
        ..Default::default()
    });
    let verdict = Arc::new(Mutex::new(None));
    let client = Client {
        host_keys,
        verdict: verdict.clone(),
    };
    let handshake = tokio::time::timeout(
        timeout,
        russh::client::connect_stream(config, stream, client),
    )
    .await
    .map_err(within(Stage::Handshake))?;
    let mut ssh = match handshake {
        Ok(ssh) => ssh,
        Err(e) => {
            let decided = verdict.lock().take();
            return Err(match decided {
                Some(HostKeyVerdict::Changed { offered }) => OpenError::HostKeyChanged { offered },
                Some(HostKeyVerdict::Unavailable(why)) => transient("HOST_KEY_UNRECORDED", why),
                _ => transient("SSH_FAILED", handshake_failure(&e)),
            });
        }
    };
    tokio::time::timeout(timeout, login(&mut ssh, target, creds))
        .await
        .map_err(within(Stage::Login))??;

    let start_sftp = async {
        let channel = ssh
            .channel_open_session()
            .await
            .map_err(|e| no_channel(&e))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| no_sftp(&e))?;
        let config = russh_sftp::client::Config {
            // Our own stall check ends a read that makes no progress; this only bounds a lost
            // reply.
            request_timeout_secs: 120,
            ..Default::default()
        };
        let mut sftp = RawSftpSession::new_with_config(channel.into_stream(), config);
        let version = sftp.init().await.map_err(|e| sftp_init_failed(&e))?;
        let mut read_len = READ_CHUNK;
        if version
            .extensions
            .get("limits@openssh.com")
            .is_some_and(|v| v == "1")
            && let Ok(limits) = sftp.limits().await
        {
            let limits = russh_sftp::client::rawsession::Limits::from(limits);
            if let Some(max) = limits.read_len {
                read_len = read_len
                    .min(u32::try_from(max).unwrap_or(u32::MAX))
                    .max(1024);
            }
            sftp.set_limits(limits);
        }
        Ok::<_, OpenError>((sftp, read_len))
    };
    let (sftp, read_len) = tokio::time::timeout(timeout, start_sftp)
        .await
        .map_err(within(Stage::Sftp))??;
    Ok(Session {
        ssh,
        sftp: Arc::new(sftp),
        read_len,
    })
}

/// An SFTP failure in the job's words. [`RemoteError::text`] is the message a person reads;
/// `Display` is its English.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// The path does not exist.
    Missing,
    /// The server refused this operation on this file (permission, failure, a path that is a
    /// folder…): it concerns the file, not the connection. The server's words, or ours.
    Refused(Text),
    /// The connection or the request was lost (timeout, closed session).
    Lost(Text),
}

impl RemoteError {
    /// The server did not answer in time.
    #[must_use]
    pub fn no_answer() -> Self {
        Self::Lost(tr!(
            "the server did not answer",
            "伺服器沒有回應",
            "サーバーが応答しませんでした"
        ))
    }

    /// The failure, in the three languages (the server's own words as they are).
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Missing => tr!(
                "The remote file or folder does not exist",
                "遠端檔案或資料夾不存在",
                "リモートのファイルまたはフォルダーが存在しません"
            ),
            Self::Refused(m) => tr!(
                "The server refused: {m}",
                "伺服器拒絕：{m}",
                "サーバーが拒否しました：{m}";
                m = m.clone()
            ),
            Self::Lost(m) => tr!(
                "The connection to the server was broken: {m}",
                "與伺服器的連線中斷：{m}",
                "サーバーとの接続が切断されました：{m}";
                m = m.clone()
            ),
        }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text().en)
    }
}

#[must_use]
pub fn remote_error(e: russh_sftp::client::error::Error) -> RemoteError {
    use russh_sftp::client::error::Error as E;
    match e {
        E::Status(s) if s.status_code == StatusCode::NoSuchFile => RemoteError::Missing,
        E::Status(s) => {
            RemoteError::Refused(Text::verbatim(if s.error_message.trim().is_empty() {
                format!("{:?}", s.status_code)
            } else {
                s.error_message
            }))
        }
        E::Limited(m) => RemoteError::Refused(Text::verbatim(m)),
        E::Timeout => RemoteError::no_answer(),
        E::IO(m) | E::UnexpectedBehavior(m) => RemoteError::Lost(Text::verbatim(m)),
        E::UnexpectedPacket => RemoteError::Lost(tr!(
            "an unexpected answer arrived",
            "收到不符預期的回應",
            "予期しない応答を受信しました"
        )),
    }
}
