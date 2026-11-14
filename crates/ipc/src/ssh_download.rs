//! Controller → manager calls of the SSH download component (`Call::SshDownload`).
//!
//! The controller checks request shapes and relays; the manager checks the job against the host
//! (local folder, key file, Gateway), keeps its secrets in the vault and runs it.

use serde::{Deserialize, Serialize};
use vpn_domain::{
    SshDownloadAction, SshDownloadCleared, SshDownloadDirCheck, SshDownloadJob, SshDownloadJobId,
    SshDownloadLog, SshDownloadStatus, SshDownloadTransfers, SshDownloadView,
};

use crate::secret::SecretBytes;

/// What an input does to one secret of a job.
#[derive(Debug, Serialize, Deserialize)]
pub enum SecretChange {
    /// Keep the stored one (or none).
    Keep,
    /// Store this one (it replaces the stored one).
    Set(SecretBytes),
    /// Remove the stored one.
    Clear,
}

impl SecretChange {
    /// Whether the job has this secret after the change, given whether it had one before.
    #[must_use]
    pub const fn present(&self, before: bool) -> bool {
        match self {
            Self::Keep => before,
            Self::Set(_) => true,
            Self::Clear => false,
        }
    }
}

/// The secrets of a job's input.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobSecrets {
    pub password: SecretChange,
    pub key_passphrase: SecretChange,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SshDownloadCall {
    /// Every job with its status.
    List,
    Get(SshDownloadJobId),
    /// `job` with the secret fields of the stored job (none for a new one); the manager resolves
    /// them with `secrets`.
    Create {
        job: Box<SshDownloadJob>,
        secrets: JobSecrets,
        paused: bool,
    },
    Update {
        job: Box<SshDownloadJob>,
        expected_revision: u64,
        secrets: JobSecrets,
    },
    /// Stop the job and delete it with its state, records and log (remote files in its working
    /// folder stay where they are).
    Delete {
        id: SshDownloadJobId,
        expected_revision: u64,
    },
    Action {
        id: SshDownloadJobId,
        action: SshDownloadAction,
        fingerprint: Option<String>,
    },
    /// A page of the job's file records: the unfinished ones, or the finished ones before the
    /// cursor, newest first.
    Transfers {
        id: SshDownloadJobId,
        finished: bool,
        before: Option<String>,
        limit: u32,
    },
    /// The newest lines of the job's log.
    Log {
        id: SshDownloadJobId,
        limit: u32,
    },
    /// Delete every line of the job's log (nothing of it is left in the database).
    ClearLog {
        id: SshDownloadJobId,
    },
    /// Delete the job's finished records; unfinished ones stay (their files resume). Files are
    /// never touched.
    ClearHistory {
        id: SshDownloadJobId,
    },
    /// Whether a local folder can take downloads (nothing is created).
    CheckDir {
        path: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SshDownloadReply {
    Views(Vec<SshDownloadView>),
    View(Box<SshDownloadView>),
    Status(Box<SshDownloadStatus>),
    Transfers(SshDownloadTransfers),
    Log(SshDownloadLog),
    Cleared(SshDownloadCleared),
    DirCheck(SshDownloadDirCheck),
    Unit,
}
