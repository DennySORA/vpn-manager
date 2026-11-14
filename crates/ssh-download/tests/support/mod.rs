//! A test world for SSH download: a Store with a Gateway entity, an in-process SSH/SFTP server
//! (russh's server side over a real temporary folder), and a fake Gateway on 127.0.0.1 that speaks
//! SOCKS5 with the installation-key proof and then runs the SSH server on the same stream. The
//! fake Gateway can refuse (SOCKS 0x02), cut a connection after some bytes, and counts everything,
//! so a test can prove what was — and what was not — connected.

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::BoxFuture;
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use vpn_domain::*;
use vpn_ipc::identity::{GATEWAY_AUTH_METHOD, GATEWAY_MARK_SSH_PULL, gateway_proof};
use vpn_ipc::ssh_download::{JobSecrets, SecretChange, SshDownloadCall, SshDownloadReply};
use vpn_ssh_download::{Gateway, Options, Publish, Route, Routes, SshDownloads};
use vpn_store::Store;
use vpn_sync::Mutex;
use zeroize::Zeroizing;

/// The installation key the fake Gateway proves itself with.
pub const GATEWAY_KEY: [u8; 32] = [9; 32];
/// The name the job connects to; the fake Gateway checks it arrives unresolved.
pub const HOST: &str = "sftp.test";
pub const USER: &str = "puller";

pub fn key(seed: u8) -> PrivateKey {
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])),
        "",
    )
    .expect("ed25519 key")
}

pub fn fp(k: &PrivateKey) -> String {
    vpn_ssh_download::session::fingerprint(k.public_key())
}

/// Options with short waits.
pub const fn fast() -> Options {
    Options {
        connect_timeout: Duration::from_secs(5),
        stall_timeout: Duration::from_secs(3),
        idle_close: Duration::from_millis(300),
        vpn_backoff: (Duration::from_millis(100), Duration::from_millis(400)),
        retry_backoff: (Duration::from_millis(100), Duration::from_millis(400)),
        local_retry: Duration::from_millis(500),
        max_connections: 16,
        read_budget: 128 * 1024 * 1024,
        large_file: 64 * 1024 * 1024,
        publish_every: Duration::from_millis(50),
        upkeep_every: Duration::from_secs(3600),
    }
}

// ---------------------------------------------------------------------------------------------
// The SSH/SFTP server
// ---------------------------------------------------------------------------------------------

/// A fault only in the size verification after downloading through an open handle.
#[derive(Clone, Copy, Debug)]
pub enum FinalStatFault {
    Refused,
    Missing,
    /// No size from the handle, and none from the path either while the fault lasts.
    MissingSize,
    ChangedSize,
}

/// The server's state, shared by every connection.
pub struct Server {
    pub root: PathBuf,
    pub host_key: Mutex<PrivateKey>,
    pub client_key: PublicKey,
    pub password: Mutex<Option<String>>,
    /// Files whose open is refused (permission denied).
    pub deny_read: Mutex<HashSet<String>>,
    /// Each read waits this long (to catch a transfer in flight).
    pub read_delay: Mutex<Duration>,
    /// SSH sessions that reached the server.
    pub sessions: AtomicU32,
    /// Login attempts, per host key fingerprint the server presented.
    pub logins: Mutex<HashMap<String, u32>>,
    /// Reads served: (SSH session number, file name, offset).
    pub reads: Mutex<Vec<(u32, String, u64)>>,
    pub read_bytes: AtomicU64,
    pub final_stat_fault: Mutex<Option<FinalStatFault>>,
    pub final_stat_faults: AtomicU32,
    /// A server that never reports the size of an open handle (the path still has one).
    pub handle_omits_size: AtomicBool,
    /// Files opened for reading, by name, in order.
    pub opens: Mutex<Vec<String>>,
    /// What each SSH session may still send to its client before its connection breaks.
    pub cuts: Mutex<HashMap<u32, Arc<AtomicI64>>>,
    /// The session that next opens a file another open came before (a connection that helps
    /// with a file) breaks after this many more bytes to its client.
    pub cut_second_opener: Mutex<Option<i64>>,
    /// Before such an open, the file is replaced by another one with these bytes (and the same
    /// modification time): the earlier handle still reads the old one.
    pub replace_for_second_opener: Mutex<Option<Vec<u8>>>,
}

impl Server {
    pub fn new(root: PathBuf, host_key: PrivateKey, client_key: PublicKey) -> Arc<Self> {
        for d in ["todo", "doing", "failed"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Arc::new(Self {
            root,
            host_key: Mutex::new(host_key),
            client_key,
            password: Mutex::new(None),
            deny_read: Mutex::new(HashSet::new()),
            read_delay: Mutex::new(Duration::ZERO),
            sessions: AtomicU32::new(0),
            logins: Mutex::new(HashMap::new()),
            reads: Mutex::new(Vec::new()),
            read_bytes: AtomicU64::new(0),
            final_stat_fault: Mutex::new(None),
            final_stat_faults: AtomicU32::new(0),
            handle_omits_size: AtomicBool::new(false),
            opens: Mutex::new(Vec::new()),
            cuts: Mutex::new(HashMap::new()),
            cut_second_opener: Mutex::new(None),
            replace_for_second_opener: Mutex::new(None),
        })
    }

    pub fn put(&self, dir: &str, name: &str, data: &[u8]) {
        std::fs::write(self.root.join(dir).join(name), data).unwrap();
    }

    pub fn names(&self, dir: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.root.join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn logins_for(&self, fp: &str) -> u32 {
        self.logins.lock().get(fp).copied().unwrap_or(0)
    }

    pub fn logins_with(&self, k: &PrivateKey) -> u32 {
        self.logins_for(&fp(k))
    }

    /// The offset of the first read of each SSH session, in session order.
    pub fn first_reads(&self) -> Vec<(u32, u64)> {
        let mut seen = std::collections::BTreeMap::new();
        for (s, _, off) in self.reads.lock().iter() {
            seen.entry(*s).or_insert(*off);
        }
        seen.into_iter().collect()
    }
}

struct SshConn {
    server: Arc<Server>,
    session: u32,
    presented: String,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl SshConn {
    fn login(&self) {
        *self
            .server
            .logins
            .lock()
            .entry(self.presented.clone())
            .or_default() += 1;
    }
}

impl russh::server::Handler for SshConn {
    type Error = russh::Error;

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        self.login();
        let ok = user == USER && self.server.password.lock().as_deref() == Some(password);
        std::future::ready(Ok(if ok { Auth::Accept } else { Auth::reject() }))
    }

    fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        self.login();
        let ok = user == USER && key.public_key.key_data() == self.server.client_key.key_data();
        std::future::ready(Ok(if ok { Auth::Accept } else { Auth::reject() }))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(session.close(channel))
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&id)) {
            ("sftp", Some(channel)) => {
                session.channel_success(id)?;
                russh_sftp::server::run(
                    channel.into_stream(),
                    Fs {
                        server: self.server.clone(),
                        session: self.session,
                        files: HashMap::new(),
                        fstat_calls: HashMap::new(),
                        dirs: HashMap::new(),
                        next: 0,
                    },
                )
                .await;
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }
}

/// SFTP over the server's root folder.
struct Fs {
    server: Arc<Server>,
    session: u32,
    files: HashMap<String, (String, std::fs::File)>,
    fstat_calls: HashMap<String, u32>,
    dirs: HashMap<String, Option<Vec<File>>>,
    next: u32,
}

fn status_of(e: &io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

impl Fs {
    fn path(&self, p: &str) -> PathBuf {
        self.server.root.join(p.trim_start_matches('/'))
    }

    fn handle(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}{}", self.next)
    }

    fn open_now(&mut self, id: u32, filename: &str) -> Result<Handle, StatusCode> {
        let name = Path::new(filename)
            .file_name()
            .map_or_default(|n| n.to_string_lossy().into_owned());
        if self
            .server
            .deny_read
            .lock()
            .iter()
            .any(|d| filename.contains(d.as_str()))
        {
            return Err(StatusCode::PermissionDenied);
        }
        if self.server.opens.lock().contains(&name) {
            if let Some(left) = self.server.cut_second_opener.lock().take()
                && let Some(cut) = self.server.cuts.lock().get(&self.session)
            {
                cut.store(left, Ordering::SeqCst);
            }
            let other = self.server.replace_for_second_opener.lock().take();
            if let Some(bytes) = other {
                let path = self.path(filename);
                let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
                let other = path.with_extension("other");
                std::fs::write(&other, bytes).unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&other)
                    .unwrap()
                    .set_modified(modified)
                    .unwrap();
                std::fs::rename(&other, &path).unwrap();
            }
        }
        let f = std::fs::File::open(self.path(filename)).map_err(|e| status_of(&e))?;
        let h = self.handle("f");
        self.server.opens.lock().push(name.clone());
        self.files.insert(h.clone(), (name, f));
        Ok(Handle { id, handle: h })
    }

    fn close_now(&mut self, id: u32, handle: &str) -> Status {
        self.files.remove(handle);
        self.fstat_calls.remove(handle);
        self.dirs.remove(handle);
        ok(id)
    }

    fn fstat_now(&mut self, id: u32, handle: &str) -> Result<Attrs, StatusCode> {
        let (_, f) = self.files.get(handle).ok_or(StatusCode::Failure)?;
        let m = f.metadata().map_err(|e| status_of(&e))?;
        let mut attrs = FileAttributes::from(&m);
        if self.server.handle_omits_size.load(Ordering::SeqCst) {
            attrs.size = None;
        }
        let calls = self.fstat_calls.entry(handle.to_owned()).or_default();
        *calls += 1;
        if *calls >= 2
            && let Some(fault) = *self.server.final_stat_fault.lock()
        {
            self.server.final_stat_faults.fetch_add(1, Ordering::SeqCst);
            match fault {
                FinalStatFault::Refused => return Err(StatusCode::PermissionDenied),
                FinalStatFault::Missing => return Err(StatusCode::NoSuchFile),
                FinalStatFault::MissingSize => attrs.size = None,
                FinalStatFault::ChangedSize => {
                    attrs.size = attrs.size.map(|size| size.saturating_add(1));
                }
            }
        }
        Ok(Attrs { id, attrs })
    }

    fn stat_now(&self, id: u32, path: &str) -> Result<Attrs, StatusCode> {
        let m = std::fs::metadata(self.path(path)).map_err(|e| status_of(&e))?;
        let mut attrs = FileAttributes::from(&m);
        if matches!(
            *self.server.final_stat_fault.lock(),
            Some(FinalStatFault::MissingSize)
        ) {
            attrs.size = None;
        }
        Ok(Attrs { id, attrs })
    }

    fn lstat_now(&self, id: u32, path: &str) -> Result<Attrs, StatusCode> {
        let m = std::fs::symlink_metadata(self.path(path)).map_err(|e| status_of(&e))?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    fn opendir_now(&mut self, id: u32, path: &str) -> Result<Handle, StatusCode> {
        let mut entries = Vec::new();
        for e in std::fs::read_dir(self.path(path)).map_err(|e| status_of(&e))? {
            let e = e.map_err(|e| status_of(&e))?;
            let m = std::fs::symlink_metadata(e.path()).map_err(|e| status_of(&e))?;
            entries.push(File::new(
                e.file_name().to_string_lossy(),
                FileAttributes::from(&m),
            ));
        }
        let h = self.handle("d");
        self.dirs.insert(h.clone(), Some(entries));
        Ok(Handle { id, handle: h })
    }

    fn readdir_now(&mut self, id: u32, handle: &str) -> Result<Name, StatusCode> {
        self.dirs
            .get_mut(handle)
            .map_or(Err(StatusCode::Failure), |slot| match slot.take() {
                Some(files) if !files.is_empty() => Ok(Name { id, files }),
                _ => Err(StatusCode::Eof),
            })
    }

    fn rename_now(&self, id: u32, old: &str, new: &str) -> Result<Status, StatusCode> {
        let (from, to) = (self.path(old), self.path(new));
        // SFTP v3 (OpenSSH): an existing target is not replaced.
        if to.exists() {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(from, to).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }

    fn remove_now(&self, id: u32, filename: &str) -> Result<Status, StatusCode> {
        std::fs::remove_file(self.path(filename)).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }

    fn mkdir_now(&self, id: u32, path: &str) -> Result<Status, StatusCode> {
        std::fs::create_dir(self.path(path)).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }
}

impl russh_sftp::server::Handler for Fs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    fn open(
        &mut self,
        id: u32,
        filename: String,
        _flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        std::future::ready(self.open_now(id, &filename))
    }

    fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Ok(self.close_now(id, &handle)))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let delay = *self.server.read_delay.lock();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let (name, f) = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read_at(&mut buf, offset).map_err(|e| status_of(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        self.server
            .reads
            .lock()
            .push((self.session, name.clone(), offset));
        self.server
            .read_bytes
            .fetch_add(n as u64, Ordering::Relaxed);
        Ok(Data { id, data: buf })
    }

    fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        std::future::ready(self.fstat_now(id, &handle))
    }

    fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        std::future::ready(self.stat_now(id, &path))
    }

    fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        std::future::ready(self.lstat_now(id, &path))
    }

    fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        std::future::ready(self.opendir_now(id, &path))
    }

    fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        std::future::ready(self.readdir_now(id, &handle))
    }

    fn rename(
        &mut self,
        id: u32,
        old: String,
        new: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(self.rename_now(id, &old, &new))
    }

    fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(self.remove_now(id, &filename))
    }

    fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(self.mkdir_now(id, &path))
    }

    fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        std::future::ready(Ok(Name {
            id,
            files: vec![File::dummy(path)],
        }))
    }
}

// ---------------------------------------------------------------------------------------------
// The fake Gateway
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// SOCKS5 succeeds and the SSH server answers.
    Serve,
    /// SOCKS5 refuses with 0x02 (the connection is not ready).
    Refuse,
    /// SOCKS5 succeeds, but the far end never answers (a server behind the tunnel that hangs).
    Stall,
}

/// A stream that breaks after `left` bytes towards the client (a connection lost mid-transfer).
struct Cut {
    inner: TcpStream,
    /// Bytes to the client before the connection breaks.
    left: Arc<AtomicI64>,
}

impl AsyncRead for Cut {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Cut {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.left.load(Ordering::SeqCst) <= 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.left
                .fetch_sub(i64::try_from(*n).unwrap_or(i64::MAX), Ordering::SeqCst);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct FakeGateway {
    pub port: u16,
    pub mode: Mutex<Mode>,
    /// TCP connections accepted.
    pub accepted: AtomicU32,
    /// CONNECT requests and where they asked to go.
    pub connects: Mutex<Vec<(u8, String, u16)>>,
    /// The next connection breaks after this many bytes to the client.
    pub cut_next: Mutex<Option<i64>>,
    /// The SSH sessions it carries now (ended all at once by `drop_all`).
    open: Mutex<Vec<russh::server::Handle>>,
    server: Arc<Server>,
}

impl FakeGateway {
    pub async fn start(server: Arc<Server>) -> Arc<Self> {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw = Arc::new(Self {
            port: l.local_addr().unwrap().port(),
            mode: Mutex::new(Mode::Serve),
            accepted: AtomicU32::new(0),
            connects: Mutex::new(Vec::new()),
            cut_next: Mutex::new(None),
            open: Mutex::new(Vec::new()),
            server,
        });
        let me = gw.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                me.accepted.fetch_add(1, Ordering::SeqCst);
                let gw = me.clone();
                tokio::spawn(async move {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "a client that goes away mid-handshake ends its connection with an I/O error; the tests look at what the Gateway recorded"
                    )]
                    let _ = gw.serve(s).await;
                });
            }
        });
        gw
    }

    /// End every SSH session it carries (the server restarts).
    pub async fn drop_all(&self) {
        let open: Vec<russh::server::Handle> = self.open.lock().drain(..).collect();
        for h in open {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "a session that already ended cannot be disconnected again; ending every session is all that matters"
            )]
            let _ = h
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "restart".into(),
                    "en".into(),
                )
                .await;
        }
    }

    async fn serve(&self, mut s: TcpStream) -> io::Result<()> {
        let mut hello = [0u8; 4];
        s.read_exact(&mut hello).await?;
        assert_eq!(
            hello,
            [0x05, 0x02, GATEWAY_AUTH_METHOD, GATEWAY_MARK_SSH_PULL],
            "only the private methods are offered: the proof, and the SSH 下載 mark"
        );
        s.write_all(&[0x05, GATEWAY_AUTH_METHOD]).await?;
        let mut nonce = [0u8; 32];
        s.read_exact(&mut nonce).await?;
        s.write_all(&gateway_proof(&GATEWAY_KEY, &nonce)).await?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        let host = match head[3] {
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                s.read_exact(&mut name).await?;
                String::from_utf8_lossy(&name).into_owned()
            }
            0x01 => {
                let mut a = [0u8; 4];
                s.read_exact(&mut a).await?;
                std::net::Ipv4Addr::from(a).to_string()
            }
            _ => {
                let mut a = [0u8; 16];
                s.read_exact(&mut a).await?;
                std::net::Ipv6Addr::from(a).to_string()
            }
        };
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        self.connects.lock().push((head[3], host.clone(), port));
        let mode = *self.mode.lock();
        let code = if mode == Mode::Refuse || host != HOST {
            0x02
        } else {
            0x00
        };
        s.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        if code != 0 {
            return Ok(());
        }
        if mode == Mode::Stall {
            let mut buf = [0u8; 256];
            while s.read(&mut buf).await? > 0 {}
            return Ok(());
        }
        let left = Arc::new(AtomicI64::new(
            self.cut_next.lock().take().unwrap_or(i64::MAX),
        ));
        let stream = Cut {
            inner: s,
            left: left.clone(),
        };
        let host_key = self.server.host_key.lock().clone();
        let presented = fp(&host_key);
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let session = self.server.sessions.fetch_add(1, Ordering::SeqCst) + 1;
        self.server.cuts.lock().insert(session, left);
        let conn = SshConn {
            server: self.server.clone(),
            session,
            presented,
            channels: HashMap::new(),
        };
        if let Ok(running) = russh::server::run_stream(config, stream, conn).await {
            self.open.lock().push(running.handle());
            #[expect(
                clippy::let_underscore_must_use,
                reason = "a session ends with an error whenever a test cuts or drops its connection"
            )]
            let _ = running.await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Routes, Store, the component
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Ready,
    Waiting,
}

pub struct TestRoutes {
    pub port: u16,
    pub kind: Mutex<RouteKind>,
    /// Routes asked for.
    pub asked: AtomicU32,
    changes: watch::Sender<u64>,
}

impl TestRoutes {
    pub fn new(port: u16, kind: RouteKind) -> Arc<Self> {
        Arc::new(Self {
            port,
            kind: Mutex::new(kind),
            asked: AtomicU32::new(0),
            changes: watch::Sender::new(0),
        })
    }

    /// The connection's state changed (as an Instance status event does).
    pub fn set(&self, kind: RouteKind) {
        *self.kind.lock() = kind;
        self.changes.send_modify(|n| *n += 1);
    }
}

impl Routes for TestRoutes {
    fn route(&self, _gateway: GatewayId) -> BoxFuture<'_, Route> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let kind = *self.kind.lock();
            match kind {
                RouteKind::Ready => Route::Ready(Gateway {
                    port: self.port,
                    key: Arc::new(Zeroizing::new(GATEWAY_KEY)),
                }),
                RouteKind::Waiting => Route::Waiting {
                    code: "VPN_NOT_READY",
                    reason: "連線「測試」未就緒".into(),
                },
            }
        })
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

/// A Store with one Gateway entity (a job must name one that exists).
pub async fn store(dir: &Path) -> (Arc<Store>, GatewayId) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = Arc::new(Store::open(dir, &Zeroizing::new([4u8; 32]), 1).unwrap());
    let now = Timestamp::now();
    let meta = EntityMeta {
        revision: 1,
        created_at: now,
        updated_at: now,
    };
    let key: WgKey = "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhISE="
        .parse()
        .unwrap();
    let profile = store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta.clone(),
            name: "p".into(),
            provider: ProviderKind::Generic,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: SecretRef(SecretId::new()),
                public_key: key,
                addresses: vec!["10.0.0.2/32".parse().unwrap()],
                dns: vec![],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: key,
                preshared_key: None,
                endpoint: "203.0.113.1:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let instance = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta.clone(),
            name: "測試".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: TransportRef::default(),
        })
        .await
        .unwrap();
    let gateway = store
        .create(GatewaySpec {
            id: GatewayId::new(),
            meta,
            instance_id: instance.id,
            name: "socks".into(),
            kind: GatewayKind::Socks5,
            port: 1080,
            enabled: true,
            udp: false,
            max_connections: 64,
        })
        .await
        .unwrap();
    (store, gateway.id)
}

/// Every status the component published, in order.
#[derive(Default, Clone)]
pub struct Statuses(pub Arc<Mutex<Vec<SshDownloadStatus>>>);

impl Statuses {
    pub fn publish(&self) -> Publish {
        let v = self.0.clone();
        Arc::new(move |s| v.lock().push(s))
    }
}

/// Everything one test uses.
pub struct World {
    pub tmp: tempfile::TempDir,
    pub store: Arc<Store>,
    pub gateway_id: GatewayId,
    pub server: Arc<Server>,
    pub gateway: Arc<FakeGateway>,
    pub routes: Arc<TestRoutes>,
    pub statuses: Statuses,
    pub local: PathBuf,
    pub key_file: PathBuf,
}

impl World {
    pub async fn new(route: RouteKind) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let (store, gateway_id) = store(&tmp.path().join("state")).await;
        let client = key(1);
        let server = Server::new(
            tmp.path().join("remote"),
            key(2),
            client.public_key().clone(),
        );
        let gateway = FakeGateway::start(server.clone()).await;
        let routes = TestRoutes::new(gateway.port, route);
        let key_file = tmp.path().join("id_ed25519");
        std::fs::write(
            &key_file,
            client.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            local: tmp.path().join("downloads"),
            tmp,
            store,
            gateway_id,
            server,
            gateway,
            routes,
            statuses: Statuses::default(),
            key_file,
        }
    }

    pub async fn start(&self) -> Arc<SshDownloads> {
        self.start_with(fast()).await
    }

    pub async fn start_with(&self, opts: Options) -> Arc<SshDownloads> {
        SshDownloads::start(
            self.store.clone(),
            self.routes.clone(),
            self.statuses.publish(),
            opts,
        )
        .await
        .unwrap()
    }

    pub fn job(&self) -> SshDownloadJob {
        let now = Timestamp::now();
        SshDownloadJob {
            id: SshDownloadJobId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: now,
                updated_at: now,
            },
            name: "測試下載".into(),
            gateway_id: self.gateway_id,
            host: HOST.into(),
            port: 22,
            user: USER.into(),
            identity_file: Some(self.key_file.display().to_string()),
            key_passphrase: None,
            password: None,
            source_dir: "/todo".into(),
            work_dir: "/doing".into(),
            failed_dir: "/failed".into(),
            local_dir: self.local.display().to_string(),
            connections: 2,
            retries: 2,
            retry_backoff_secs: 1,
            scan_interval_secs: 3600,
            name_filter: SshDownloadNameFilter::All,
            skip_hidden: true,
            record_names: true,
            history_days: None,
        }
    }

    pub fn local_names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.local).map_or_default(|d| {
            d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n != vpn_ssh_download::local::PARTIAL_DIR)
                .collect()
        });
        v.sort();
        v
    }

    pub fn partials(&self) -> Vec<String> {
        std::fs::read_dir(self.local.join(vpn_ssh_download::local::PARTIAL_DIR)).map_or_default(
            |d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            },
        )
    }
}

pub const fn keep() -> JobSecrets {
    JobSecrets {
        password: SecretChange::Keep,
        key_passphrase: SecretChange::Keep,
    }
}

pub async fn create(
    d: &SshDownloads,
    job: SshDownloadJob,
    secrets: JobSecrets,
) -> Result<SshDownloadView, ApiError> {
    match d
        .call(SshDownloadCall::Create {
            job: Box::new(job),
            secrets,
            paused: false,
        })
        .await?
    {
        SshDownloadReply::View(v) => Ok(*v),
        _ => panic!("not a view"),
    }
}

pub async fn action(
    d: &SshDownloads,
    id: SshDownloadJobId,
    action: SshDownloadAction,
    fingerprint: Option<String>,
) -> Result<SshDownloadStatus, ApiError> {
    match d
        .call(SshDownloadCall::Action {
            id,
            action,
            fingerprint,
        })
        .await?
    {
        SshDownloadReply::Status(s) => Ok(*s),
        _ => panic!("not a status"),
    }
}

pub async fn history(d: &SshDownloads, id: SshDownloadJobId) -> Vec<SshDownloadTransfer> {
    match d
        .call(SshDownloadCall::Transfers {
            id,
            finished: true,
            before: None,
            limit: 200,
        })
        .await
        .unwrap()
    {
        SshDownloadReply::Transfers(t) => t.items,
        _ => panic!("not transfers"),
    }
}

pub async fn log(d: &SshDownloads, id: SshDownloadJobId) -> Vec<SshDownloadLogEntry> {
    match d
        .call(SshDownloadCall::Log { id, limit: 500 })
        .await
        .unwrap()
    {
        SshDownloadReply::Log(l) => l.items,
        _ => panic!("not a log"),
    }
}

/// The job's finished transfers once there are at least `n`: a file is in place a moment before
/// its record says so, so a test that saw the file waits for the record too.
pub async fn history_of(
    d: &SshDownloads,
    id: SshDownloadJobId,
    n: usize,
) -> Vec<SshDownloadTransfer> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let records = history(d, id).await;
        if records.len() >= n {
            return records;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {n} finished transfers, {} so far",
            records.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The job's log once `cond` holds for it: a file's "downloaded" line follows its record, so a
/// test that saw the record waits for the line too.
pub async fn log_until(
    d: &SshDownloads,
    id: SshDownloadJobId,
    what: &str,
    cond: impl Fn(&[SshDownloadLogEntry]) -> bool,
) -> Vec<SshDownloadLogEntry> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let lines = log(d, id).await;
        if cond(&lines) {
            return lines;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}: {lines:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait (up to `secs`) until `cond` holds.
pub async fn until(secs: u64, what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Deterministic test content.
pub fn content(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| i.to_le_bytes()[0].wrapping_mul(31).wrapping_add(seed))
        .collect()
}
