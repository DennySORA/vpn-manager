//! What a job keeps about a file in its log and history: the file's name and the paths that hold
//! it — or, for a job that does not record names (`record_names` off), its transfer number only
//! (`#3f2a9c1d`). A file that is not finished keeps its name in its record until it is: that is
//! what it resumes with (the remote copy waits in the working folder under the record's id).

use vpn_domain::{SshDownloadJob, Text, ssh_download_label};
use vpn_store::SshDownloadTransferRow;

/// Names shorter than this are not looked for inside other text (they would match words).
const MIN_NAME_TO_SCRUB: usize = 3;

/// How the job's log refers to the file of `row`.
pub fn file_ref(job: &SshDownloadJob, row: &SshDownloadTransferRow) -> String {
    if job.record_names {
        row.name.clone()
    } else {
        ssh_download_label(&row.id)
    }
}

/// `text` (a reason, a server's message) as the job may keep it: for a job that does not record
/// names, every path of the file and the name itself are replaced by its transfer number, in
/// each language.
pub fn scrub(job: &SshDownloadJob, row: &SshDownloadTransferRow, text: &Text) -> Text {
    if job.record_names {
        return text.clone();
    }
    text.map(|_, words| scrub_words(row, words))
}

/// [`scrub`] of one language's words.
fn scrub_words(row: &SshDownloadTransferRow, text: &str) -> String {
    let label = ssh_download_label(&row.id);
    let mut out = text.to_owned();
    let paths = [
        row.final_path.as_deref(),
        row.failed_path.as_deref(),
        Some(row.source_path.as_str()),
    ];
    for path in paths.into_iter().flatten().filter(|p| !p.is_empty()) {
        out = out.replace(path, &label);
    }
    if row.name.chars().count() >= MIN_NAME_TO_SCRUB {
        out = out.replace(&row.name, &label);
    }
    out
}

/// The record as the job keeps it in its history. For a job that does not record names a
/// finished file keeps its transfer number for a name, no path that holds the name (the failed
/// folder only, for a failed one) and a scrubbed reason; an empty `source_path` marks it so.
pub fn kept(job: &SshDownloadJob, row: &SshDownloadTransferRow) -> SshDownloadTransferRow {
    if job.record_names || row.finished_ms.is_none() {
        return row.clone();
    }
    SshDownloadTransferRow {
        name: ssh_download_label(&row.id),
        source_path: String::new(),
        final_path: None,
        failed_path: row.failed_path.as_ref().map(|_| job.failed_dir.clone()),
        error: row.error.as_ref().map(|e| scrub(job, row, e)),
        ..row.clone()
    }
}

/// Whether `row`, written as [`kept`] makes it, leaves earlier images with the name behind (the
/// WAL is then scrubbed).
pub const fn forgets_name(job: &SshDownloadJob, row: &SshDownloadTransferRow) -> bool {
    !job.record_names && row.finished_ms.is_some()
}
