//! SSH download end to end, against an in-process SSH/SFTP server behind a fake Gateway that
//! speaks SOCKS5 with the installation-key proof: download, finalize and remote delete; resume
//! after a broken connection and after a manager restart; the failed folder; no connection at all
//! while the Gateway cannot carry it (fail closed); a changed host key stops the job; a clear
//! forgets one job's names for good while its unfinished file still resumes.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use support::*;
use vpn_domain::*;

/// No names: what a folder that must be empty is compared with, so a failure shows what is in it.
const NONE: [&str; 0] = [];
use std::assert_matches;
use vpn_ipc::ssh_download::{SshDownloadCall, SshDownloadReply};
use vpn_ssh_download::SshDownloads;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_are_downloaded_put_in_place_and_deleted_remotely() {
    let w = World::new(RouteKind::Ready).await;
    let first = content(300_000, 1);
    let second = content(1, 2);
    w.server.put("todo", "a.bin", &first);
    w.server.put("todo", "b 中文.txt", &second);
    w.server.put("todo", "empty", b"");
    // Left alone: a hidden upload in progress and a folder.
    w.server.put("todo", ".c.part", b"x");
    std::fs::create_dir(w.server.root.join("todo/sub")).unwrap();
    let d = w.start().await;
    let v = create(&d, w.job(), keep()).await.unwrap();
    let id = v.job.id;
    until(20, "three files downloaded", || w.local_names().len() == 3).await;
    until(10, "remote copies deleted", || {
        w.server.names("doing").is_empty()
    })
    .await;
    assert_eq!(w.local_names(), ["a.bin", "b 中文.txt", "empty"]);
    assert_eq!(std::fs::read(w.local.join("a.bin")).unwrap(), first);
    assert_eq!(std::fs::read(w.local.join("b 中文.txt")).unwrap(), second);
    assert_eq!(std::fs::read(w.local.join("empty")).unwrap(), b"");
    assert_eq!(w.server.names("todo"), [".c.part", "sub"]);
    assert!(w.partials().is_empty(), "{:?}", w.partials());
    let records = history(&d, id).await;
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|t| t.state == SshDownloadTransferState::Completed && t.error.is_none()),
        "{records:?}"
    );
    let a_rec = records.iter().find(|t| t.name == "a.bin").unwrap();
    assert_eq!(a_rec.size, Some(Counter(300_000)));
    assert_eq!(
        a_rec.local_path.as_deref(),
        Some(w.local.join("a.bin").display().to_string().as_str())
    );
    // Every connection went through the Gateway, with the name unresolved.
    let connects = w.gateway.connects.lock().clone();
    assert_ne!(connects, []);
    assert!(
        connects
            .iter()
            .all(|(atyp, host, port)| *atyp == 0x03 && host == HOST && *port == 22),
        "{connects:?}"
    );
    let status = d.status(id).await.unwrap();
    assert_eq!(status.completed, 3);
    assert_eq!(status.bytes, Counter(300_001));
    // The SSH streams to the Gateway carried at least the files, encrypted and framed.
    assert!(
        status.wire_rx_bytes.0 > 300_001 && status.wire_tx_bytes.0 > 0,
        "{status:?}"
    );
    assert!(status.running_since.is_some(), "{status:?}");
    assert_eq!(
        status.last_scan_skipped, 2,
        "the hidden file and the folder"
    );
    assert_eq!(
        status.host_key.unwrap().fingerprint,
        fp(&key(2)),
        "trusted on first use"
    );
    // Statuses were published, at most one per job and tick.
    assert!(!w.statuses.0.lock().is_empty());
    let lines = log(&d, id).await;
    assert!(
        lines.iter().any(|l| l.code == "HOST_KEY_RECORDED"),
        "{lines:?}"
    );
    assert_eq!(lines.iter().filter(|l| l.code == "DOWNLOADED").count(), 3);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_taken_locally_gets_a_unique_name_and_nothing_is_replaced() {
    let w = World::new(RouteKind::Ready).await;
    std::fs::create_dir_all(&w.local).unwrap();
    std::fs::write(w.local.join("report.pdf"), b"mine").unwrap();
    w.server.put("todo", "report.pdf", b"theirs");
    let d = w.start().await;
    let id = create(&d, w.job(), keep()).await.unwrap().job.id;
    until(20, "downloaded", || w.local_names().len() == 2).await;
    assert_eq!(std::fs::read(w.local.join("report.pdf")).unwrap(), b"mine");
    let other = w
        .local_names()
        .into_iter()
        .find(|n| n != "report.pdf")
        .unwrap();
    assert!(
        other.starts_with("report--")
            && std::path::Path::new(&other)
                .extension()
                .is_some_and(|e| e == "pdf"),
        "{other}"
    );
    assert_eq!(std::fs::read(w.local.join(&other)).unwrap(), b"theirs");
    let h = history(&d, id).await;
    assert!(h[0].local_path.as_deref().unwrap().ends_with(&other));
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_connection_resumes_where_the_partial_file_ends() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(2 * 1024 * 1024, 7);
    w.server.put("todo", "big.iso", &data);
    // The first connection breaks after about 700 KiB towards the client.
    *w.gateway.cut_next.lock() = Some(700 * 1024);
    let d = w.start().await;
    let mut job = w.job();
    job.connections = 1;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    until(30, "downloaded", || w.local_names() == ["big.iso"]).await;
    assert_eq!(std::fs::read(w.local.join("big.iso")).unwrap(), data);
    // The session after the break started reading where the partial file ended, not at 0.
    let firsts = w.server.first_reads();
    assert!(firsts.len() >= 2, "the connection never broke: {firsts:?}");
    assert!(
        firsts[1..].iter().all(|(_, off)| *off > 0),
        "a resume started from 0: {firsts:?}"
    );
    let served = w.server.read_bytes.load(Ordering::Relaxed);
    assert!(
        served < (data.len() as u64) * 3,
        "{served} bytes served for {}",
        data.len()
    );
    assert!(
        w.gateway.accepted.load(Ordering::SeqCst) >= 2,
        "it reconnected"
    );
    let h = history(&d, id).await;
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert!(w.server.names("doing").is_empty() && w.server.names("todo").is_empty());
    d.shutdown().await;
}

/// An unverifiable source must survive even after every payload byte arrived locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn final_size_verification_keeps_the_source_until_it_can_be_confirmed() {
    for fault in [
        FinalStatFault::Refused,
        FinalStatFault::Missing,
        FinalStatFault::MissingSize,
        FinalStatFault::ChangedSize,
    ] {
        let w = World::new(RouteKind::Ready).await;
        let data = content(64 * 1024, 31);
        w.server.put("todo", "checked.bin", &data);
        *w.server.final_stat_fault.lock() = Some(fault);
        let d = w.start().await;
        let mut job = w.job();
        job.connections = 1;
        job.retries = 20;
        let id = create(&d, job, keep()).await.unwrap().job.id;
        // A second rejection proves the earlier error was recorded and retried.
        until(20, "final size checks refused", || {
            w.server.final_stat_faults.load(Ordering::SeqCst) >= 2
        })
        .await;
        assert!(w.local_names().is_empty(), "{fault:?}");
        assert!(history(&d, id).await.is_empty(), "{fault:?}");
        let working = w.server.names("doing");
        assert_eq!(working.len(), 1, "{fault:?}");
        assert_eq!(
            std::fs::read(w.server.root.join("doing").join(&working[0])).unwrap(),
            data,
            "{fault:?}"
        );

        *w.server.final_stat_fault.lock() = None;
        until(20, "confirmed download completed", || {
            w.statuses
                .0
                .lock()
                .last()
                .is_some_and(|status| status.completed == 1)
        })
        .await;
        let records = history(&d, id).await;
        assert_eq!(records.len(), 1, "{fault:?}");
        assert_eq!(records[0].state, SshDownloadTransferState::Completed);
        assert!(records[0].error.is_none(), "{records:?}");
        assert_eq!(std::fs::read(w.local.join("checked.bin")).unwrap(), data);
        assert_eq!(w.server.names("doing"), NONE);
        assert_eq!(w.partials(), NONE);
        d.shutdown().await;
    }
}

/// A server that reports no size for an open handle is asked by path, before and after the
/// download: its files are delivered, not held back until they land in the failed folder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_size_the_handle_does_not_report_is_read_from_the_path() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(200_000, 43);
    w.server.put("todo", "plain.bin", &data);
    w.server.handle_omits_size.store(true, Ordering::SeqCst);
    let d = w.start().await;
    let mut job = w.job();
    job.connections = 1;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    until(20, "the file is delivered", || {
        w.statuses
            .0
            .lock()
            .last()
            .is_some_and(|status| status.completed == 1)
    })
    .await;
    assert_eq!(std::fs::read(w.local.join("plain.bin")).unwrap(), data);
    assert_eq!(w.server.names("doing"), NONE);
    assert_eq!(w.server.names("failed"), NONE);
    assert_eq!(w.partials(), NONE);
    let records = history(&d, id).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, SshDownloadTransferState::Completed);
    assert!(records[0].error.is_none(), "{records:?}");
    d.shutdown().await;
}

/// An unwritable partial path keeps each source safe until that file recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_write_recovery_keeps_other_files_pending_on_the_same_connection() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(32 * 1024, 19);
    for name in ["a.bin", "b.bin"] {
        w.server.put("todo", name, &data);
    }
    w.server.deny_read.lock().insert("/doing/".into());
    let mut opts = fast();
    opts.idle_close = Duration::from_secs(30);
    let d = w.start_with(opts).await;
    let mut job = w.job();
    job.connections = 1;
    job.retries = 20;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    until(20, "both files claimed", || {
        w.server.names("doing").len() == 2
    })
    .await;
    let rows = w.store.ssh_download_open_transfers(id).await.unwrap();
    assert_eq!(rows.len(), 2);
    let blockers: Vec<_> = ["a.bin", "b.bin"]
        .iter()
        .map(|name| {
            let row = rows.iter().find(|row| row.name == *name).unwrap();
            let path = w
                .local
                .join(vpn_ssh_download::local::PARTIAL_DIR)
                .join(format!("{}.part", row.id));
            std::fs::create_dir_all(&path).unwrap();
            path
        })
        .collect();
    w.server.deny_read.lock().clear();
    // A file is opened again only after its first local failure was recorded.
    until(20, "both files failed locally and were tried again", || {
        let opens = w.server.opens.lock();
        rows.iter()
            .all(|row| opens.iter().filter(|name| **name == row.id).count() >= 2)
    })
    .await;
    // One cause, one line, with the file that met it first: a full disk fails every file of
    // the queue the same way and must not fill the job's log.
    let lines: Vec<_> = log(&d, id)
        .await
        .into_iter()
        .filter(|entry| entry.code == "LOCAL_WRITE")
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_matches!(
        lines[0].file.as_deref(),
        Some("a.bin" | "b.bin"),
        "{lines:?}"
    );
    assert_eq!(w.local_names(), NONE);
    assert_eq!(w.server.names("doing").len(), 2);
    assert_eq!(history(&d, id).await, []);

    std::fs::remove_dir(&blockers[1]).unwrap();
    until(20, "second file recovered", || {
        w.statuses
            .0
            .lock()
            .last()
            .is_some_and(|status| status.completed == 1)
    })
    .await;
    assert_eq!(std::fs::read(w.local.join("b.bin")).unwrap(), data);
    assert_eq!(w.server.names("doing").len(), 1);
    let status = d.status(id).await.unwrap();
    assert_eq!(status.reason_code.as_deref(), Some("LOCAL_WRITE"));
    assert!(status.next_retry_at.is_some());
    assert!(blockers[0].is_dir(), "the first failure is still present");

    std::fs::remove_dir(&blockers[0]).unwrap();
    until(20, "both files recovered", || {
        w.statuses
            .0
            .lock()
            .last()
            .is_some_and(|status| status.completed == 2)
    })
    .await;
    let status = d.status(id).await.unwrap();
    assert!(status.reason_code.is_none(), "{status:?}");
    assert!(status.next_retry_at.is_none(), "{status:?}");
    assert_eq!(w.server.sessions.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(w.local.join("a.bin")).unwrap(), data);
    assert_eq!(w.server.names("doing"), NONE);
    assert_eq!(w.partials(), NONE);
    let records = history(&d, id).await;
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|row| row.error.is_none()), "{records:?}");
    d.shutdown().await;
}

/// A source replaced by another file of the same length while a download waits to resume is
/// downloaded again from the start: the local file is never a mix of the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_replaced_between_attempts_is_downloaded_again_from_the_start() {
    let w = World::new(RouteKind::Ready).await;
    let first = content(2 * 1024 * 1024, 7);
    let second = content(2 * 1024 * 1024, 11);
    w.server.put("todo", "swap.iso", &first);
    *w.gateway.cut_next.lock() = Some(700 * 1024);
    let d = w.start().await;
    let mut job = w.job();
    job.connections = 1;
    job.retry_backoff_secs = 3;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    // The first attempt broke and left a part of the first version behind.
    tokio::time::timeout(Duration::from_secs(30), async {
        while !log(&d, id).await.iter().any(|e| e.code == "ATTEMPT_FAILED") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first attempt failed");
    assert_eq!(w.local_names(), NONE);
    let working = w.server.names("doing");
    assert_eq!(working.len(), 1);
    std::fs::write(w.server.root.join("doing").join(&working[0]), &second).unwrap();

    until(30, "downloaded", || w.local_names() == ["swap.iso"]).await;
    assert!(
        std::fs::read(w.local.join("swap.iso")).unwrap() == second,
        "the local file is not the second version from its first byte"
    );
    assert!(
        log(&d, id).await.iter().any(|e| e.code == "SOURCE_CHANGED"),
        "the change was not noticed"
    );
    until(10, "remote copy deleted", || {
        w.server.names("doing").is_empty()
    })
    .await;
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert_eq!(w.partials(), NONE);
    d.shutdown().await;
}

/// After a crash, a file that merely has the name and the size the record expects is not taken
/// for the download: the source stays until the download itself is in place beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_with_the_name_and_size_of_a_download_is_not_taken_for_it() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(1024 * 1024, 3);
    let theirs = content(1024 * 1024, 99);
    w.server.put("todo", "movie.mkv", &data);
    *w.server.read_delay.lock() = Duration::from_millis(100);
    let d = w.start().await;
    let mut job = w.job();
    job.connections = 1;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    until(30, "a partial file", || !w.partials().is_empty()).await;
    d.shutdown().await;
    drop(d);
    // The state a crash right after the old placing would leave, with another file under the
    // name: the record at "finalizing", no partial file, a file of the same name and size.
    let mut row = w
        .store
        .ssh_download_open_transfers(id)
        .await
        .unwrap()
        .remove(0);
    let partial = w
        .local
        .join(vpn_ssh_download::local::PARTIAL_DIR)
        .join(format!("{}.part", row.id));
    std::fs::remove_file(&partial).unwrap();
    std::fs::write(w.local.join("movie.mkv"), &theirs).unwrap();
    row.state = SshDownloadTransferState::Finalizing;
    row.size = Some(data.len() as u64);
    row.final_path = Some(w.local.join("movie.mkv").display().to_string());
    w.store.update_ssh_download_transfer(row).await.unwrap();
    *w.server.read_delay.lock() = Duration::ZERO;

    let d = w.start().await;
    until(30, "the download is in place beside it", || {
        w.local_names().len() == 2
    })
    .await;
    assert!(
        std::fs::read(w.local.join("movie.mkv")).unwrap() == theirs,
        "the other file was touched"
    );
    let ours = w
        .local_names()
        .into_iter()
        .find(|n| n != "movie.mkv")
        .unwrap();
    assert!(
        std::fs::read(w.local.join(&ours)).unwrap() == data,
        "the download is not complete"
    );
    until(10, "remote copy deleted", || {
        w.server.names("doing").is_empty()
    })
    .await;
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert!(h[0].local_path.as_deref().unwrap().ends_with(&ours));
    assert_eq!(w.partials(), NONE);
    d.shutdown().await;
}

/// Options under which a file of a few MiB is a large one: the job's idle connections help.
const fn helping() -> vpn_ssh_download::Options {
    vpn_ssh_download::Options {
        large_file: 256 * 1024,
        ..fast()
    }
}

/// The SSH sessions that served reads of the one file a test downloads.
fn sessions_that_read(w: &World) -> usize {
    let sessions: std::collections::HashSet<u32> =
        w.server.reads.lock().iter().map(|r| r.0).collect();
    sessions.len()
}

/// A large file fetched over several of the job's connections is the source byte for byte:
/// every read lands where it was read from, whichever connection served it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_fetched_over_several_connections_is_the_source_byte_for_byte() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(16 * 1024 * 1024 + 4321, 5);
    w.server.put("todo", "large.bin", &data);
    *w.server.read_delay.lock() = Duration::from_millis(10);
    let d = w.start_with(helping()).await;
    let mut job = w.job();
    job.connections = 3;
    let id = create(&d, job, keep()).await.unwrap().job.id;

    until(60, "downloaded", || w.local_names() == ["large.bin"]).await;
    assert!(
        std::fs::read(w.local.join("large.bin")).unwrap() == data,
        "the local file is not the source"
    );
    assert!(
        sessions_that_read(&w) >= 2,
        "only one connection fetched the file: the test proved nothing about helpers"
    );
    until(10, "remote copy deleted", || {
        w.server.names("doing").is_empty()
    })
    .await;
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert_eq!(w.partials(), NONE);
    d.shutdown().await;
}

/// A connection that helps and breaks in the middle leaves no gap and does not fail the file:
/// the reads it had taken are asked again on the connection that still answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_loses_its_connection_leaves_no_gap() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(16 * 1024 * 1024, 9);
    w.server.put("todo", "large.bin", &data);
    *w.server.read_delay.lock() = Duration::from_millis(10);
    // After its checks (two ends of 64 KiB) the helper serves one read and breaks in the next.
    *w.server.cut_second_opener.lock() = Some(300 * 1024);
    let d = w.start_with(helping()).await;
    let mut job = w.job();
    job.connections = 2;
    let id = create(&d, job, keep()).await.unwrap().job.id;

    until(60, "downloaded", || w.local_names() == ["large.bin"]).await;
    assert!(
        std::fs::read(w.local.join("large.bin")).unwrap() == data,
        "the local file is not the source"
    );
    assert!(
        w.server.cut_second_opener.lock().is_none() && sessions_that_read(&w) >= 2,
        "no helper took part: the test proved nothing"
    );
    assert!(
        !log(&d, id).await.iter().any(|e| e.code == "ATTEMPT_FAILED"),
        "the helper's broken connection failed the file's attempt"
    );
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert_eq!(w.partials(), NONE);
    d.shutdown().await;
}

/// A connection that comes to help and finds another file under the path (the same size and
/// time, other bytes) serves nothing, and the attempt is not published: the next one sees the
/// change and downloads the file that is there now, from its first byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_finds_another_file_ends_the_attempt() {
    let w = World::new(RouteKind::Ready).await;
    let first = content(16 * 1024 * 1024, 7);
    let second = content(16 * 1024 * 1024, 11);
    w.server.put("todo", "swap.iso", &first);
    *w.server.read_delay.lock() = Duration::from_millis(10);
    *w.server.replace_for_second_opener.lock() = Some(second.clone());
    let d = w.start_with(helping()).await;
    let mut job = w.job();
    job.connections = 2;
    let id = create(&d, job, keep()).await.unwrap().job.id;

    until(60, "downloaded", || w.local_names() == ["swap.iso"]).await;
    assert!(
        std::fs::read(w.local.join("swap.iso")).unwrap() == second,
        "the local file is not the file that was under the path at the end"
    );
    let entries = log(&d, id).await;
    assert!(
        entries
            .iter()
            .any(|e| e.code == "ATTEMPT_FAILED" && e.message.zh_tw.contains("不同的檔案")),
        "the attempt that read two files was not ended"
    );
    assert!(
        entries.iter().any(|e| e.code == "SOURCE_CHANGED"),
        "the next attempt did not start again from the first byte"
    );
    until(10, "remote copy deleted", || {
        w.server.names("doing").is_empty()
    })
    .await;
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert_eq!(w.partials(), NONE);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_manager_restart_continues_the_unfinished_file_from_its_record() {
    let w = World::new(RouteKind::Ready).await;
    let data = content(2 * 1024 * 1024, 3);
    w.server.put("todo", "movie.mkv", &data);
    *w.server.read_delay.lock() = Duration::from_millis(100);
    let d = w.start().await;
    let mut job = w.job();
    job.connections = 1;
    let id = create(&d, job, keep()).await.unwrap().job.id;
    // In flight: some bytes are in the partial file.
    until(30, "a partial file", || {
        w.partials().iter().any(|p| {
            std::fs::metadata(w.local.join(vpn_ssh_download::local::PARTIAL_DIR).join(p))
                .is_ok_and(|m| m.len() > 0)
        })
    })
    .await;
    d.shutdown().await;
    drop(d);
    let open = w.store.ssh_download_open_transfers(id).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].state, SshDownloadTransferState::Downloading);
    assert_eq!(
        w.server.names("doing"),
        [open[0].id.clone()],
        "claimed into the working folder"
    );
    assert_eq!(w.server.names("todo"), NONE);
    let had = open[0].id.clone();
    let sessions_before = w.server.sessions.load(Ordering::SeqCst);
    *w.server.read_delay.lock() = Duration::ZERO;

    // The next manager.
    let d = w.start().await;
    until(30, "downloaded after the restart", || {
        w.local_names() == ["movie.mkv"]
    })
    .await;
    assert_eq!(std::fs::read(w.local.join("movie.mkv")).unwrap(), data);
    let after: Vec<(u32, u64)> = w
        .server
        .first_reads()
        .into_iter()
        .filter(|(s, _)| *s > sessions_before)
        .collect();
    assert!(
        !after.is_empty() && after.iter().all(|(_, off)| *off > 0),
        "resumed at 0: {after:?}"
    );
    let h = history(&d, id).await;
    assert_eq!(h.len(), 1, "one file, one record: {h:?}");
    assert_eq!(h[0].id, had);
    assert_eq!(h[0].state, SshDownloadTransferState::Completed);
    assert_eq!(w.server.names("doing"), NONE);
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_connected_while_the_gateway_cannot_carry_the_job() {
    let w = World::new(RouteKind::Waiting).await;
    w.server.put("todo", "a.txt", b"hello");
    let d = w.start().await;
    let id = create(&d, w.job(), keep()).await.unwrap().job.id;
    until(5, "waiting for the VPN", || {
        w.statuses
            .0
            .lock()
            .iter()
            .any(|s| s.state == SshDownloadState::WaitingVpn)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    // Fail closed: the job asked for a route again and again, and connected nowhere.
    assert!(w.routes.asked.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        w.gateway.accepted.load(Ordering::SeqCst),
        0,
        "a connection was opened without a route"
    );
    assert_eq!(w.server.sessions.load(Ordering::SeqCst), 0);
    let s = d.status(id).await.unwrap();
    assert_eq!(s.state, SshDownloadState::WaitingVpn);
    assert_eq!(s.reason_code.as_deref(), Some("VPN_NOT_READY"));
    assert_eq!(w.server.names("todo"), ["a.txt"]);

    // The route is back, but the Gateway refuses (its connection is not ready): still nothing
    // reaches the server, and the job keeps waiting.
    *w.gateway.mode.lock() = Mode::Refuse;
    w.routes.set(RouteKind::Ready);
    until(5, "the Gateway refused", || {
        w.gateway.accepted.load(Ordering::SeqCst) >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        w.server.sessions.load(Ordering::SeqCst),
        0,
        "an SSH session without the Gateway's consent"
    );
    let s = d.status(id).await.unwrap();
    assert_eq!(s.state, SshDownloadState::WaitingVpn);
    assert_eq!(s.reason_code.as_deref(), Some("GATEWAY_REFUSED"));
    assert!(s.reason.unwrap().zh_tw.contains("不會改走一般網路"));

    // The Gateway carries it: the job goes on by itself.
    *w.gateway.mode.lock() = Mode::Serve;
    until(20, "downloaded once the VPN is back", || {
        w.local_names() == ["a.txt"]
    })
    .await;
    let lines = log(&d, id).await;
    assert!(lines.iter().any(|l| l.code == "VPN_NOT_READY"), "{lines:?}");
    assert!(lines.iter().any(|l| l.code == "CONNECTED"), "{lines:?}");
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_host_key_stops_the_job_until_the_user_trusts_it() {
    let w = World::new(RouteKind::Ready).await;
    w.server.put("todo", "one.txt", b"1");
    let d = w.start().await;
    let id = create(&d, w.job(), keep()).await.unwrap().job.id;
    until(20, "the first file", || w.local_names() == ["one.txt"]).await;
    // The server is reinstalled: the connections drop and it presents another key.
    let new = key(3);
    *w.server.host_key.lock() = new.clone();
    w.gateway.drop_all().await;
    w.server.put("todo", "two.txt", b"2");
    action(&d, id, SshDownloadAction::Scan, None).await.unwrap();
    until(10, "stopped for the user", || {
        w.statuses
            .0
            .lock()
            .last()
            .is_some_and(|s| s.state == SshDownloadState::Error)
    })
    .await;
    let s = d.status(id).await.unwrap();
    assert_eq!(s.reason_code.as_deref(), Some("HOST_KEY_CHANGED"));
    assert_eq!(s.host_key.as_ref().unwrap().fingerprint, fp(&key(2)));
    assert_eq!(s.offered_host_key.as_ref().unwrap().fingerprint, fp(&new));
    // No login was sent to the server with the unknown key, and the file was not taken.
    assert_eq!(w.server.logins_with(&new), 0);
    assert_eq!(w.server.names("todo"), ["two.txt"]);
    // It stays stopped: no new connection on its own.
    let accepted = w.gateway.accepted.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(w.gateway.accepted.load(Ordering::SeqCst), accepted);
    assert!(
        action(&d, id, SshDownloadAction::Scan, None).await.is_err(),
        "a scan does not override the stop"
    );
    // Only the key the user saw can be trusted.
    assert!(
        action(&d, id, SshDownloadAction::TrustHostKey, Some(fp(&key(4))))
            .await
            .is_err()
    );
    let s = action(&d, id, SshDownloadAction::TrustHostKey, Some(fp(&new)))
        .await
        .unwrap();
    assert_eq!(s.host_key.unwrap().fingerprint, fp(&new));
    until(20, "the second file after trusting", || {
        w.local_names() == ["one.txt", "two.txt"]
    })
    .await;
    let lines = log(&d, id).await;
    assert!(lines.iter().any(|l| l.code == "HOST_KEY_CHANGED"));
    assert!(lines.iter().any(|l| l.code == "HOST_KEY_TRUSTED"));
    d.shutdown().await;
}

/// Whether `text` is anywhere in the control database's files (the database and its WAL).
fn in_database(w: &World, text: &str) -> bool {
    let state = w.tmp.path().join("state");
    ["control.sqlite", "control.sqlite-wal"].iter().any(|f| {
        std::fs::read(state.join(f))
            .is_ok_and(|b| b.windows(text.len()).any(|win| win == text.as_bytes()))
    })
}

/// The job's log and history, read through the component (as the API shows them).
async fn records(
    d: &SshDownloads,
    id: SshDownloadJobId,
) -> (Vec<SshDownloadLogEntry>, Vec<SshDownloadTransfer>) {
    (log(d, id).await, history(d, id).await)
}

async fn cleared(d: &SshDownloads, call: SshDownloadCall) -> u32 {
    match d.call(call).await.unwrap() {
        SshDownloadReply::Cleared(c) => c.removed,
        _ => panic!("not a clear"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clear_forgets_one_jobs_names_for_good_and_its_unfinished_file_still_resumes() {
    let w = World::new(RouteKind::Ready).await;
    std::fs::create_dir_all(w.server.root.join("other/todo")).unwrap();
    w.server
        .put("todo", "cleared-secret-1.bin", &content(10_000, 1));
    w.server
        .put("other/todo", "other-kept-1.bin", &content(10_000, 2));
    let d = w.start().await;
    let mut a = w.job();
    a.connections = 1;
    let a = create(&d, a, keep()).await.unwrap().job.id;
    let mut b = w.job();
    b.name = "另一個工作".into();
    b.source_dir = "/other/todo".into();
    b.work_dir = "/other/doing".into();
    b.failed_dir = "/other/failed".into();
    b.local_dir = w.tmp.path().join("other-downloads").display().to_string();
    let b = create(&d, b, keep()).await.unwrap().job.id;
    for _ in 0..800 {
        if history(&d, a).await.len() == 1 && history(&d, b).await.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(history(&d, a).await.len(), 1, "job a finished its file");
    assert_eq!(history(&d, b).await.len(), 1, "job b finished its file");

    // A file of job a in flight: some of it is in its partial file.
    let data = content(2 * 1024 * 1024, 3);
    *w.server.read_delay.lock() = Duration::from_millis(100);
    w.server.put("todo", "resume-me.bin", &data);
    action(&d, a, SshDownloadAction::Scan, None).await.unwrap();
    until(30, "a partial file", || {
        w.partials().iter().any(|p| {
            std::fs::metadata(w.local.join(vpn_ssh_download::local::PARTIAL_DIR).join(p))
                .is_ok_and(|m| m.len() > 0)
        })
    })
    .await;
    let other_before = records(&d, b).await;
    assert!(
        in_database(&w, "cleared-secret-1.bin"),
        "the name was recorded"
    );

    // Clear job a's log and history.
    assert!(cleared(&d, SshDownloadCall::ClearLog { id: a }).await > 0);
    assert_eq!(
        cleared(&d, SshDownloadCall::ClearHistory { id: a }).await,
        1
    );
    let (lines, done) = records(&d, a).await;
    assert!(done.is_empty(), "{done:?}");
    assert!(
        lines
            .iter()
            .all(|l| { l.file.is_none() && !l.message.zh_tw.contains("cleared-secret-1.bin") }),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l.code == "LOG_CLEARED"), "{lines:?}");
    // Exactly that job's: the other one's log and history are as they were.
    assert_eq!(records(&d, b).await, other_before);
    // The file in flight keeps its record.
    let open = w.store.ssh_download_open_transfers(a).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].name, "resume-me.bin");
    // Nothing of the cleared rows is left in the database or its WAL; the rest is there.
    assert!(!in_database(&w, "cleared-secret-1.bin"));
    assert!(in_database(&w, "other-kept-1.bin"));
    assert!(in_database(&w, "resume-me.bin"));

    // The next manager resumes the unfinished file from its record.
    d.shutdown().await;
    drop(d);
    let sessions_before = w.server.sessions.load(Ordering::SeqCst);
    *w.server.read_delay.lock() = Duration::ZERO;
    let d = w.start().await;
    until(30, "the unfinished file downloaded", || {
        w.local_names().contains(&"resume-me.bin".to_string())
    })
    .await;
    assert_eq!(std::fs::read(w.local.join("resume-me.bin")).unwrap(), data);
    let after: Vec<(u32, u64)> = w
        .server
        .first_reads()
        .into_iter()
        .filter(|(s, _)| *s > sessions_before)
        .collect();
    assert!(
        !after.is_empty() && after.iter().all(|(_, off)| *off > 0),
        "resumed at 0: {after:?}"
    );
    d.shutdown().await;
}
