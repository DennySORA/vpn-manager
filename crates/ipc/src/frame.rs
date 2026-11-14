//! Length-prefixed JSON frames over a Unix stream socket, with optional file descriptors.
//!
//! JSON (not CBOR): the shared domain types use `#[serde(flatten)]` and internally tagged enums,
//! which serde buffers through a human-readable intermediate representation; a binary format
//! that reports `is_human_readable() == false` then encodes addresses differently from how they
//! are decoded. JSON keeps one representation everywhere (and the frames are small).
//!
//! Frame: `u32 BE payload length | u8 fd count | payload (JSON)`. File descriptors travel as
//! `SCM_RIGHTS` ancillary data on the same `sendmsg` as the frame's first byte; the reader keeps
//! received descriptors in arrival order and hands a frame exactly the number it declares. A
//! frame that declares descriptors which did not arrive is a protocol error.
//!
//! Lengths are checked before any allocation. Received descriptors are close-on-exec.
//!
//! A host short of network buffers refuses socket calls with `ENOBUFS` for a moment (macOS under a
//! burst of traffic, on Unix sockets too): a frame waits that out instead of ending the
//! connection, which would end the worker or the manager link with it.

#![expect(
    unsafe_code,
    reason = "this module owns the sendmsg/recvmsg SCM_RIGHTS boundary: msghdr, iovec and cmsg handling through libc"
)]

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::Instant;

const HEADER: usize = 5;
/// Most descriptors one frame may carry.
pub const MAX_FDS: usize = 64;
/// Default frame limit for control traffic.
pub const DEFAULT_MAX_FRAME: usize = 256 * 1024;

/// How long a socket may keep refusing for lack of buffer space (`ENOBUFS`), without progress,
/// before the error ends the connection.
const NOBUFS_GIVE_UP: Duration = Duration::from_secs(30);
const NOBUFS_LONGEST_WAIT: Duration = Duration::from_millis(50);

/// The waits of one frame for a host short of buffer space.
#[derive(Default)]
struct NoBufs {
    wait: Duration,
    since: Option<Instant>,
}

impl NoBufs {
    /// After a failed call: back off and return `Ok` (try again) when it was `ENOBUFS` and the
    /// bound has not passed; the error otherwise.
    async fn wait_out(&mut self, e: io::Error) -> io::Result<()> {
        if e.raw_os_error() != Some(libc::ENOBUFS) {
            return Err(e);
        }
        let now = Instant::now();
        if now.duration_since(*self.since.get_or_insert(now)) >= NOBUFS_GIVE_UP {
            return Err(e);
        }
        self.wait = (self.wait * 2).clamp(Duration::from_millis(1), NOBUFS_LONGEST_WAIT);
        tokio::time::sleep(self.wait).await;
        Ok(())
    }

    fn progressed(&mut self) {
        *self = Self::default();
    }
}

fn proto_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Encode `msg` as one frame.
///
/// # Errors
///
/// `InvalidData` when `fd_count` exceeds [`MAX_FDS`], when `msg` fails to serialize, or when the
/// payload exceeds `max` bytes (or the `u32` length field).
pub fn encode<T: Serialize>(msg: &T, fd_count: usize, max: usize) -> io::Result<Vec<u8>> {
    if fd_count > MAX_FDS {
        return Err(proto_err("too many file descriptors in one frame"));
    }
    let mut out = vec![0u8; HEADER];
    serde_json::to_writer(&mut out, msg).map_err(|e| proto_err(&format!("encode: {e}")))?;
    let len = out.len() - HEADER;
    if len > max {
        return Err(proto_err("frame exceeds the size limit"));
    }
    // A `TryFromIntError` says only "out of range", which each message states.
    let len = u32::try_from(len).map_err(|_over_u32| proto_err("frame exceeds the size limit"))?;
    let fd_count = u8::try_from(fd_count)
        .map_err(|_over_u8| proto_err("too many file descriptors in one frame"))?;
    out[..4].copy_from_slice(&len.to_be_bytes());
    out[4] = fd_count;
    Ok(out)
}

/// Write half: sends frames, with descriptors attached via `sendmsg`.
#[derive(Debug)]
pub struct FrameWriter {
    half: OwnedWriteHalf,
    max: usize,
}

/// Read half: buffers bytes and received descriptors.
#[derive(Debug)]
pub struct FrameReader {
    half: OwnedReadHalf,
    buf: BytesMut,
    fds: VecDeque<OwnedFd>,
    max: usize,
}

/// Split a connected stream into a reader and writer with the given frame limit.
pub fn split(stream: UnixStream, max_frame: usize) -> (FrameReader, FrameWriter) {
    split_with(stream, max_frame, max_frame)
}

/// [`split`] with separate limits for what this side reads and what it sends.
///
/// A peer that legitimately sends large frames one way (the manager's policy to a worker) does
/// not make the other direction accept them.
pub fn split_with(
    stream: UnixStream,
    read_max: usize,
    write_max: usize,
) -> (FrameReader, FrameWriter) {
    let (r, w) = stream.into_split();
    (
        FrameReader {
            half: r,
            buf: BytesMut::with_capacity(8192),
            fds: VecDeque::new(),
            max: read_max,
        },
        FrameWriter {
            half: w,
            max: write_max,
        },
    )
}

impl FrameWriter {
    /// Send one message. Not cancel-safe (a cancelled send may leave a partial frame); callers
    /// own the writer from a single task.
    ///
    /// # Errors
    ///
    /// Encoding errors from [`encode`], `WriteZero` when the peer closed, and socket errors
    /// (`ENOBUFS` only once it persisted past the give-up bound).
    #[expect(
        clippy::future_not_send,
        reason = "generic over the message: the future is Send whenever T is Sync, as every caller's message type is"
    )]
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "the exclusive borrow keeps a second send from interleaving with a frame that goes out in several sendmsg calls"
    )]
    pub async fn send<T: Serialize>(&mut self, msg: &T, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let frame = encode(msg, fds.len(), self.max)?;
        let stream: &UnixStream = self.half.as_ref();
        let mut sent = 0usize;
        let mut first = true;
        let mut nobufs = NoBufs::default();
        while sent < frame.len() {
            stream.writable().await?;
            let attach: &[BorrowedFd<'_>] = if first { fds } else { &[] };
            match stream.try_io(Interest::WRITABLE, || {
                send_with_fds(stream.as_raw_fd(), &frame[sent..], attach)
            }) {
                Ok(n) => {
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "peer closed"));
                    }
                    sent += n;
                    first = false;
                    nobufs.progressed();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => nobufs.wait_out(e).await?,
            }
        }
        Ok(())
    }
}

impl FrameReader {
    /// Receive the next message and the descriptors it carries. `Ok(None)` on clean EOF.
    /// Cancel-safe: partially received data stays buffered.
    ///
    /// # Errors
    ///
    /// `InvalidData` for a frame over the limit, too many declared or unclaimed descriptors,
    /// descriptors that did not arrive, a payload that does not decode, or EOF mid-frame; socket
    /// errors otherwise (`ENOBUFS` only once it persisted past the give-up bound).
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<(T, Vec<OwnedFd>)>> {
        let mut nobufs = NoBufs::default();
        loop {
            if let Some(frame) = self.try_parse()? {
                return Ok(Some(frame));
            }
            let stream: &UnixStream = self.half.as_ref();
            stream.readable().await?;
            // The chunk stays inside this block, so it is not held across the awaits below.
            let res = {
                let mut chunk = [0u8; 16 * 1024];
                stream
                    .try_io(Interest::READABLE, || {
                        recv_with_fds(stream.as_raw_fd(), &mut chunk)
                    })
                    .map(|(n, fds)| {
                        self.buf.extend_from_slice(&chunk[..n]);
                        (n, fds)
                    })
            };
            match res {
                Ok((0, _)) => {
                    return if self.buf.is_empty() {
                        Ok(None)
                    } else {
                        Err(proto_err("connection closed mid-frame"))
                    };
                }
                Ok((_, fds)) => {
                    nobufs.progressed();
                    self.fds.extend(fds);
                    if self.fds.len() > MAX_FDS * 4 {
                        return Err(proto_err("too many unclaimed file descriptors"));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => nobufs.wait_out(e).await?,
            }
        }
    }

    fn try_parse<T: DeserializeOwned>(&mut self) -> io::Result<Option<(T, Vec<OwnedFd>)>> {
        if self.buf.len() < HEADER {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        let nfds = self.buf[4] as usize;
        if len > self.max {
            return Err(proto_err("incoming frame exceeds the size limit"));
        }
        if nfds > MAX_FDS {
            return Err(proto_err("incoming frame declares too many descriptors"));
        }
        if self.buf.len() < HEADER + len {
            self.buf.reserve(HEADER + len - self.buf.len());
            return Ok(None);
        }
        if self.fds.len() < nfds {
            return Err(proto_err("frame declares descriptors that did not arrive"));
        }
        self.buf.advance(HEADER);
        let payload = self.buf.split_to(len);
        let fds: Vec<OwnedFd> = self.fds.drain(..nfds).collect();
        let msg =
            serde_json::from_slice(&payload[..]).map_err(|e| proto_err(&format!("decode: {e}")))?;
        Ok(Some((msg, fds)))
    }
}

/// A zeroed buffer for control messages, at least `bytes` long and aligned for `cmsghdr`: the
/// headers in it are read and written in place (here and inside the `CMSG_*` helpers), which needs
/// that alignment and a `Vec<u8>` does not promise it.
fn control_buffer(bytes: usize) -> Vec<libc::cmsghdr> {
    // SAFETY: a `cmsghdr` holds only integers, for which all zeros is a valid value.
    let zero: libc::cmsghdr = unsafe { std::mem::zeroed() };
    vec![zero; bytes.div_ceil(size_of::<libc::cmsghdr>())]
}

fn send_with_fds(fd: RawFd, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let fd_bytes = size_of_val(raw.as_slice());
    // A `TryFromIntError` says only "out of range", which the message states.
    let fd_bytes_u32 = u32::try_from(fd_bytes)
        .map_err(|_over_u32| proto_err("too many file descriptors in one frame"))?;
    let space = if raw.is_empty() {
        0
    } else {
        // SAFETY: CMSG_SPACE is a pure size computation.
        unsafe { libc::CMSG_SPACE(fd_bytes_u32) }
    };
    let mut control = control_buffer(space as usize);
    // SAFETY: zero-initialised msghdr is valid; all pointers below point into live buffers that
    // outlive the sendmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if !raw.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = space as _;
        // SAFETY: `msg` is a live msghdr; CMSG_FIRSTHDR reads only its control pointer and length.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        // SAFETY: CMSG_LEN is a pure size computation.
        let cmsg_len = unsafe { libc::CMSG_LEN(fd_bytes_u32) };
        // SAFETY: the control length, CMSG_SPACE(fd_bytes), is more than one header, so `cmsg` is
        // the start of `control`: live, aligned for `cmsghdr`, and reached through no other
        // reference while `header` lives.
        let header = unsafe { &mut *cmsg };
        header.cmsg_level = libc::SOL_SOCKET;
        header.cmsg_type = libc::SCM_RIGHTS;
        header.cmsg_len = cmsg_len as _;
        // SAFETY: `cmsg` is the first header in `control`; CMSG_DATA steps just past it, inside
        // the CMSG_SPACE(fd_bytes) bytes of `control`.
        let fd_data = unsafe { libc::CMSG_DATA(cmsg) };
        // SAFETY: control has CMSG_SPACE(fd_bytes) bytes, so the first header and its `fd_bytes`
        // of data fit; `raw` is a separate live buffer of exactly `fd_bytes` bytes.
        unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr().cast::<u8>(), fd_data, fd_bytes) };
    }
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: msg is fully initialised and its buffers are valid for the call.
    let n = unsafe { libc::sendmsg(fd, &raw const msg, flags) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n.cast_unsigned())
    }
}

fn recv_with_fds(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // A `TryFromIntError` says only "out of range", which the message states.
    let max_fd_bytes = u32::try_from(MAX_FDS * size_of::<RawFd>())
        .map_err(|_over_u32| proto_err("descriptor buffer exceeds u32"))?;
    // SAFETY: pure size computation.
    let space = unsafe { libc::CMSG_SPACE(max_fd_bytes) };
    let mut control = control_buffer(space as usize);
    // SAFETY: zero-initialised msghdr is valid; buffers outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = space as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: msg is fully initialised and its buffers are valid for the call.
    let n = unsafe { libc::recvmsg(fd, &raw mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    // Iterating the control buffer the kernel just filled, bounded by msg_controllen.
    // SAFETY: `msg` is a live msghdr; CMSG_FIRSTHDR reads only its control pointer and length.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: a non-null header from CMSG_FIRSTHDR or CMSG_NXTHDR lies whole inside the
        // msg_controllen bytes of `control` the kernel filled, at an aligned offset of a buffer
        // aligned for `cmsghdr`; nothing writes `control` while `header` lives.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: `cmsg` is a header inside `control`; CMSG_DATA steps just past it.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            let len = header.cmsg_len as usize - (data as usize - cmsg as usize);
            // SAFETY: the header's data (`cmsg_len` minus the header) lies inside the bytes of
            // `control` the kernel just wrote, and nothing writes them while `bytes` lives.
            let bytes = unsafe { std::slice::from_raw_parts(data, len) };
            // The descriptors, read byte-wise: cmsg data need not be aligned for them.
            for raw in bytes.as_chunks::<{ size_of::<RawFd>() }>().0 {
                // SAFETY: the kernel installed this descriptor in this process for this message
                // (SCM_RIGHTS) and nothing else owns it, so `owned` is its only owner.
                let owned = unsafe { OwnedFd::from_raw_fd(RawFd::from_ne_bytes(*raw)) };
                #[cfg(not(target_os = "linux"))]
                // SAFETY: `owned` is an open descriptor; F_SETFD with FD_CLOEXEC changes only its
                // close-on-exec flag.
                unsafe {
                    libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC)
                };
                fds.push(owned);
            }
        }
        // SAFETY: `msg` is live and `cmsg` is one of its headers; CMSG_NXTHDR returns the next
        // header inside msg_controllen, or null.
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        // Descriptors were dropped by the kernel; the stream can no longer be trusted.
        return Err(proto_err("ancillary data truncated"));
    }
    // n >= 0 was checked above.
    Ok((n.cast_unsigned(), fds))
}
