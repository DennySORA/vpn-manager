//! Linux implementation of the strict sandbox.

mod access;
mod app;
pub mod caps;
mod holder;
mod landlock;
mod lease;
mod mounts;
mod net;
mod wire;

pub use access::AccessChannel;
pub use app::{APP_ROLE, AppBackend, AppEntry, run_app};
pub use caps::drop_all as caps_drop_all;
pub use holder::run_holder;
pub use lease::{
    SandboxClient, SandboxLease, SandboxProcess, WorkerEntry, detect, discover, listening, probe,
    same_process, underlay_socket,
};
