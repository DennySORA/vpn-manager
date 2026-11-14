//! Subcommand groups. Each group is one module with a clap `Subcommand` enum (or arguments) and
//! an async `run(&Ctx, …) -> CmdResult`; `main.rs` lists the groups. Adding a group: a module
//! here, one variant in `main.rs`'s `Command` and one arm in its `dispatch`.

pub mod app;
pub mod ban;
pub mod blocklist;
pub mod doctor;
pub mod forward;
pub mod gateway;
pub mod instance;
pub mod performance;
pub mod profile;
pub mod provider;
pub mod recovery;
pub mod secret;
pub mod ssh;
pub mod ssh_download;
pub mod status;
pub mod transport;

use std::fmt::Write as _;

use vpn_domain::{ApiError, InstanceView, Operation, Text};

use crate::client::Client;
use crate::output::Out;

/// What one invocation works with.
pub struct Ctx {
    pub client: Client,
    pub out: Out,
}

/// How `vpnctl` ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Ok = 0,
    /// The request was answered and did not succeed (or a check failed).
    Failed = 1,
    /// The command line was wrong (unknown or ambiguous name, missing confirmation).
    Usage = 2,
    /// A change may or may not have happened; it was not repeated.
    Unknown = 3,
}

/// Why a command did not complete.
#[derive(Debug)]
pub enum Failure {
    Usage(String),
    /// The controller could not be reached at all (nothing was sent).
    Unreachable(String),
    /// The controller answered with an error.
    Api(ApiError),
    /// The outcome of a change is unknown; `key` is its Idempotency-Key.
    Unknown {
        key: Option<String>,
        operation: Option<Box<Operation>>,
        why: String,
    },
    /// The answer could not be read.
    Invalid(String),
}

impl Failure {
    pub const fn exit(&self) -> Exit {
        match self {
            Self::Usage(_) => Exit::Usage,
            Self::Unknown { .. } => Exit::Unknown,
            Self::Unreachable(_) | Self::Api(_) | Self::Invalid(_) => Exit::Failed,
        }
    }

    /// The failure as one JSON object (`--json`). Every `message` has the shape of the API's
    /// (`{"en", "zh-TW", "ja"}`); vpnctl's own words are Traditional Chinese in all three.
    pub fn to_json(&self) -> serde_json::Value {
        let own = |m: &str| Text::verbatim(m);
        match self {
            Self::Usage(m) => {
                serde_json::json!({ "error": { "code": "USAGE", "message": own(m) } })
            }
            Self::Unreachable(m) => {
                serde_json::json!({ "error": { "code": "UNREACHABLE", "message": own(m) } })
            }
            Self::Api(e) => serde_json::json!({ "error": e }),
            Self::Unknown {
                key,
                operation,
                why,
            } => serde_json::json!({
                "error": { "code": "OUTCOME_UNKNOWN", "message": own(why) },
                "idempotency_key": key,
                "operation": operation,
            }),
            Self::Invalid(m) => {
                serde_json::json!({ "error": { "code": "INVALID_RESPONSE", "message": own(m) } })
            }
        }
    }

    /// The failure in a few lines of text (stderr).
    pub fn to_text(&self) -> String {
        match self {
            Self::Usage(m) | Self::Unreachable(m) | Self::Invalid(m) => m.clone(),
            Self::Api(e) => {
                let mut s = e.message.zh_tw.clone();
                for f in &e.field_errors {
                    let _ = write!(s, "\n  {}：{}", f.path, f.message.zh_tw);
                }
                if let Some(op) = e.operation_id {
                    let _ = write!(s, "\n  operation {op}");
                }
                s
            }
            Self::Unknown {
                key,
                operation,
                why,
            } => {
                let mut s = format!("結果未知，沒有重送：{why}");
                if let Some(op) = operation {
                    let _ = write!(s, "\n  operation {}（{:?}）", op.id, op.status);
                }
                if let Some(k) = key {
                    let _ = write!(
                        s,
                        "\n  Idempotency-Key {k}；稍後可查 GET /v1/operations/by-key/{k}"
                    );
                }
                s
            }
        }
    }
}

pub type CmdResult = Result<Exit, Failure>;

/// Every Instance with its status (shared by several groups).
pub async fn instances(ctx: &Ctx) -> Result<Vec<InstanceView>, Failure> {
    ctx.client.get("/v1/instances").await
}

/// The Instance a command names (unique name, id or id prefix).
pub async fn instance(ctx: &Ctx, query: &str) -> Result<InstanceView, Failure> {
    let all = instances(ctx).await?;
    crate::resolve::pick(
        &all,
        query,
        "連線",
        |v| v.spec.id.to_string(),
        |v| v.spec.name.clone(),
    )
    .cloned()
}
