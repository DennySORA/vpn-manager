//! Mount-namespace setup of a sandbox.
//!
//! A network namespace does not stop pathname UNIX sockets: an App could still ask
//! systemd-resolved or nscd to resolve names on the host, talk to D-Bus (and through it to
//! anything), or reach VPN Manager's own sockets. So the sandbox's mount namespace covers every
//! directory where such sockets live with an empty private tmpfs: `/run` (with `/var/run`),
//! `$XDG_RUNTIME_DIR`, `/tmp`, `/var/tmp`, `/dev/shm`, and VPN Manager's data and runtime
//! directories (those read-only). `resolv.conf` names only the sandbox's own resolver. Abstract
//! UNIX sockets are per network namespace and need nothing.
//!
//! All mounts are private to the sandbox (propagation is cut first), so the host sees nothing,
//! and they vanish with the namespace.
#![expect(
    unsafe_code,
    reason = "this module owns the sandbox's mount(2) syscalls"
)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Contents of the sandbox's `resolv.conf`.
pub const RESOLV_CONF: &str = "# VPN Manager strict sandbox: names are resolved through this connection's tunnel only.\nnameserver 127.0.0.53\noptions edns0\n";
/// Where the private `resolv.conf` is kept when it has to be bind-mounted.
const RESOLV_SOURCE: &str = "/run/.vpn-manager-resolv.conf";

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let fstype = fstype
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let target = cstr(target)?;
    // SAFETY: all pointers are valid C strings or null, alive for the call.
    let r = unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Lexically resolve `target` (absolute, or relative to `base`) without touching the
/// filesystem: `/etc/../run/x` → `/run/x`.
fn lexical(base: &Path, target: &Path) -> PathBuf {
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        base.join(target)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// One directory to cover.
struct Hide {
    path: PathBuf,
    /// tmpfs options (mode, size).
    options: &'static str,
    read_only: bool,
}

/// The directories to cover, canonical, without duplicates or paths already under another one
/// (a covered parent hides them anyway).
fn plan(xdg_runtime_dir: Option<&Path>, private: &[PathBuf]) -> Vec<Hide> {
    let mut wanted: Vec<(PathBuf, &'static str, bool)> = vec![
        ("/run".into(), "mode=0755,size=64m", false),
        ("/var/run".into(), "mode=0755,size=64m", false),
        ("/tmp".into(), "mode=1777", false),
        ("/var/tmp".into(), "mode=1777", false),
        ("/dev/shm".into(), "mode=1777", false),
    ];
    if let Some(x) = xdg_runtime_dir.filter(|p| p.is_absolute()) {
        wanted.push((x.to_path_buf(), "mode=0700,size=64m", false));
    }
    for p in private {
        wanted.push((p.clone(), "mode=0700,size=4k", true));
    }
    let mut hides: Vec<Hide> = Vec::new();
    let mut resolved: Vec<(PathBuf, &'static str, bool)> = wanted
        .into_iter()
        .filter_map(|(p, o, ro)| {
            let real = std::fs::canonicalize(&p).ok()?;
            real.is_dir().then_some((real, o, ro))
        })
        .collect();
    resolved.sort_by_key(|(p, _, _)| p.components().count());
    for (path, options, read_only) in resolved {
        if hides.iter().any(|h| path.starts_with(&h.path)) {
            continue;
        }
        hides.push(Hide {
            path,
            options,
            read_only,
        });
    }
    hides
}

/// Cover the host's socket directories and install the private `resolv.conf`. Runs inside the
/// new user + mount namespaces, before any App exists.
pub fn setup(xdg_runtime_dir: Option<&Path>, private: &[PathBuf]) -> io::Result<()> {
    // Nothing done here may propagate back to the host.
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    let hides = plan(xdg_runtime_dir, private);
    for h in &hides {
        let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
        if h.read_only {
            flags |= libc::MS_RDONLY | libc::MS_NOEXEC;
        }
        mount(
            Some("tmpfs"),
            &h.path,
            Some("tmpfs"),
            flags,
            Some(h.options),
        )
        .map_err(|e| io::Error::new(e.kind(), format!("cover {}: {e}", h.path.display())))?;
    }
    // Keep $XDG_RUNTIME_DIR a valid, private, empty directory for the Apps.
    if let Some(x) = xdg_runtime_dir.filter(|p| p.is_absolute())
        && !x.exists()
    {
        std::fs::create_dir_all(x)?;
        std::fs::set_permissions(x, std::fs::Permissions::from_mode(0o700))?;
    }
    let covered: Vec<PathBuf> = hides.into_iter().map(|h| h.path).collect();
    resolv_conf(&covered)
}

/// The mount namespace of one managed App's tree, made from the host's view by the App's
/// launcher (inside the sandbox's user namespace): the same covers as [`setup`], except that the
/// App's own directories (`keep`: its HOME, TMPDIR and working directory) stay where they are,
/// writable, when a cover would hide them.
pub fn setup_app(
    xdg_runtime_dir: Option<&Path>,
    private: &[PathBuf],
    keep: &[PathBuf],
) -> io::Result<()> {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    // Opened before anything covers them; bound back from these descriptors. A directory that
    // is (or contains) one of the private ones is never kept: that would undo its cover.
    let private_real: Vec<PathBuf> = private
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    let kept: Vec<(PathBuf, OwnedFd)> = keep
        .iter()
        .filter_map(|p| {
            let real = std::fs::canonicalize(p).ok()?;
            if private_real.iter().any(|x| x.starts_with(&real)) {
                return None;
            }
            let dir = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(&real)
                .ok()?;
            Some((real, OwnedFd::from(dir)))
        })
        .collect();
    let hides = plan(xdg_runtime_dir, private);
    for h in &hides {
        // Read-only covers are made read-only once the kept directories are back in place.
        let options = if h.read_only {
            "mode=0700,size=64k"
        } else {
            h.options
        };
        mount(
            Some("tmpfs"),
            &h.path,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(options),
        )
        .map_err(|e| io::Error::new(e.kind(), format!("cover {}: {e}", h.path.display())))?;
    }
    for (real, dir) in &kept {
        if !hides.iter().any(|h| real.starts_with(&h.path)) {
            continue;
        }
        std::fs::create_dir_all(real)?;
        let source = format!("/proc/self/fd/{}", dir.as_raw_fd());
        mount(
            Some(&source),
            real,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("keep {}: {e}", real.display())))?;
    }
    for h in hides.iter().filter(|h| h.read_only) {
        mount(
            None,
            &h.path,
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("seal {}: {e}", h.path.display())))?;
    }
    if let Some(x) = xdg_runtime_dir.filter(|p| p.is_absolute())
        && !x.exists()
    {
        std::fs::create_dir_all(x)?;
        std::fs::set_permissions(x, std::fs::Permissions::from_mode(0o700))?;
    }
    let covered: Vec<PathBuf> = hides.into_iter().map(|h| h.path).collect();
    resolv_conf(&covered)
}

/// Make `/etc/resolv.conf` name only the sandbox's resolver.
fn resolv_conf(covered: &[PathBuf]) -> io::Result<()> {
    let etc = Path::new("/etc/resolv.conf");
    let meta = match std::fs::symlink_metadata(etc) {
        Ok(m) => m,
        // Nothing to replace: the C library then asks 127.0.0.1:53, where nothing answers.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        let target = lexical(Path::new("/etc"), &std::fs::read_link(etc)?);
        if covered.iter().any(|c| target.starts_with(c)) {
            // The link points into a directory that is now our tmpfs (typically
            // systemd-resolved's stub file under /run): create the file it names.
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, RESOLV_CONF)?;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
            return Ok(());
        }
        let real = std::fs::canonicalize(etc)?;
        return bind_file(&real);
    }
    bind_file(etc)
}

fn bind_file(target: &Path) -> io::Result<()> {
    let source = Path::new(RESOLV_SOURCE);
    std::fs::write(source, RESOLV_CONF)?;
    std::fs::set_permissions(source, std::fs::Permissions::from_mode(0o644))?;
    mount(Some(RESOLV_SOURCE), target, None, libc::MS_BIND, None)?;
    // A bind mount takes its flags from a remount.
    mount(
        None,
        target,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
}

/// A fresh `/proc` for the sandbox's pid namespace, so `/proc/<pid>` of host processes (and with
/// it their root directories and namespaces) is out of reach. Called by the namespace's init.
pub fn private_proc() -> io::Result<()> {
    mount(
        Some("proc"),
        Path::new("/proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_resolution_never_touches_the_filesystem() {
        assert_eq!(
            lexical(
                Path::new("/etc"),
                Path::new("../run/systemd/resolve/stub-resolv.conf")
            ),
            PathBuf::from("/run/systemd/resolve/stub-resolv.conf")
        );
        assert_eq!(
            lexical(Path::new("/etc"), Path::new("/var/run/x/../y")),
            PathBuf::from("/var/run/y")
        );
        assert_eq!(
            lexical(Path::new("/etc"), Path::new("../../../../x")),
            PathBuf::from("/x")
        );
    }
}
