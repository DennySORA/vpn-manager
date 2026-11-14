//! Spawning a worker: a failed exec is reported at once, and only the control socket reaches
//! the child. In their own binary: a fork elsewhere in a test process would briefly hold other
//! tests' descriptors (such as flocks) until its exec.
#![expect(
    unsafe_code,
    reason = "the process tests inspect fd flags via fcntl(2)"
)]

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use vpn_platform::process::spawn_with_control_fd;

#[tokio::test]
async fn the_child_sees_only_its_control_socket() {
    use tokio::io::AsyncReadExt;
    let (ours, theirs) = UnixStream::pair().unwrap();
    // An unrelated descriptor of the parent (not close-on-exec) must not leak into the child.
    let (leak, _keep) = UnixStream::pair().unwrap();
    let leaked = leak.as_raw_fd();
    // SAFETY: reading the descriptor flags of a socket this test owns.
    let flags = unsafe { libc::fcntl(leaked, libc::F_GETFD) };
    // SAFETY: clearing FD_CLOEXEC on that socket.
    unsafe { libc::fcntl(leaked, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    let script = format!(
        "[ -e /dev/fd/3 ] && echo ok3 >&3; [ -e /dev/fd/{leaked} ] && echo leaked >&3; true"
    );
    let mut child = spawn_with_control_fd(
        Path::new("/bin/sh"),
        ["-c", script.as_str()],
        OwnedFd::from(theirs),
    )
    .unwrap();
    child.wait().await.unwrap();
    ours.set_nonblocking(true).unwrap();
    let mut s = tokio::net::UnixStream::from_std(ours).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert_eq!(out.trim(), "ok3");
}

#[test]
fn a_process_is_known_by_its_start_time_and_program_not_its_pid() {
    use vpn_platform::process::{KillOutcome, ProcessIdentity, ended, identity, kill_verified};
    let me = identity(std::process::id()).expect("own identity");
    assert_eq!(me.uid, vpn_platform::process::current_uid());
    assert!(!me.zombie);
    assert!(me.exe.is_some(), "the OS names our program");
    assert_eq!(identity(std::process::id()), Some(me), "stable");

    // A decoy that is not ours: whatever a stale record claims about its pid, it is not killed
    // unless pid, user, start time and program all match.
    let mut decoy = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = decoy.id();
    let real = identity(pid).expect("decoy identity");
    let forged = [
        ProcessIdentity {
            start: "1.000001".into(),
            ..real.clone()
        },
        ProcessIdentity {
            exe: Some("/usr/local/bin/vpnd".into()),
            ..real.clone()
        },
        ProcessIdentity {
            exe: None,
            ..real.clone()
        },
        ProcessIdentity {
            uid: real.uid + 1,
            ..real.clone()
        },
    ];
    for f in &forged {
        assert_eq!(kill_verified(f).unwrap(), KillOutcome::NotOurs, "{f:?}");
    }
    assert!(
        decoy.try_wait().unwrap().is_none(),
        "the decoy is still running"
    );
    assert!(!ended(&real));

    // The exact identity is killed.
    assert_eq!(kill_verified(&real).unwrap(), KillOutcome::Killed);
    let status = decoy.wait().unwrap();
    assert!(!status.success());
    assert!(ended(&real));
    assert_eq!(kill_verified(&real).unwrap(), KillOutcome::Gone);
}
