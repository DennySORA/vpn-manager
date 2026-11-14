//! Where one installation lives. Everything VPN Manager keeps is under its root directory — the
//! same one `vpnd` uses by default: programs in `bin/`, data and the vault key, logs in `logs/`,
//! and the installer's own record, staging area and backups in `installer/`. Only the service
//! definitions live where the supervisor requires them.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ipnetwork::IpNetwork;
use vpn_platform::paths::Paths;

use crate::fsx::{check_path, check_slug};

const ENVIRONMENTS: [&str; 4] = ["dev", "test", "lab", "prod"];

/// Which installation: the default one, or a separate one beside it (tests).
#[derive(clap::Args, Clone)]
pub struct Target {
    /// Root directory of the installation (default: the per-user application data directory).
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Environment part of the service names: dev, test, lab or prod.
    #[arg(long, default_value = "prod")]
    pub environment: String,
    /// Instance part of the service names, to keep a second installation apart.
    #[arg(long, default_value = "main")]
    pub instance: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Component {
    Manager,
    Controller,
}

impl Component {
    /// Start order; stop in reverse.
    pub const ALL: [Self; 2] = [Self::Manager, Self::Controller];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Manager => "manager",
            Self::Controller => "controller",
        }
    }
}

/// Where the web UI and API listen and for whom: installation parameters (`--port`,
/// `--listen-address`, `--allow-client`), written into the controller's service definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    pub port: u16,
    /// `127.0.0.1` (the default): this host only.
    pub address: IpAddr,
    /// Networks other hosts may use it from (a non-loopback `address` needs at least one).
    pub allow: Vec<IpNetwork>,
}

impl Listen {
    pub const DEFAULT_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// This host only, on `port`.
    #[cfg(test)]
    pub const fn loopback(port: u16) -> Self {
        Self {
            port,
            address: Self::DEFAULT_ADDRESS,
            allow: Vec::new(),
        }
    }
}

/// One supervised program: its native name and definition file.
pub struct Job {
    pub component: Component,
    pub name: String,
    pub definition: PathBuf,
    pub log: PathBuf,
}

pub struct Layout {
    pub home: PathBuf,
    pub root: PathBuf,
    /// `--root` was given: the programs are told where it is.
    pub custom_root: bool,
    pub bin: PathBuf,
    pub bin_previous: PathBuf,
    pub logs: PathBuf,
    pub installer: PathBuf,
    pub record: PathBuf,
    pub staging: PathBuf,
    pub backups: PathBuf,
    pub environment: String,
    pub instance: String,
    pub paths: Paths,
}

impl Layout {
    pub fn new(target: &Target) -> anyhow::Result<Self> {
        check_slug(&target.instance, 48).context("--instance")?;
        if !ENVIRONMENTS.contains(&target.environment.as_str()) {
            bail!("--environment 必須是 {} 之一", ENVIRONMENTS.join("、"));
        }
        let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
        let paths = match &target.root {
            Some(root) => Paths::under(&std::path::absolute(root)?),
            None => Paths::default_for_user()?,
        };
        let root = paths.state.clone();
        check_path(&root)?;
        let installer = root.join("installer");
        Ok(Self {
            bin: root.join("bin"),
            bin_previous: root.join("bin.previous"),
            logs: paths.logs(),
            record: installer.join("state.json"),
            staging: installer.join("staging"),
            backups: installer.join("backups"),
            installer,
            custom_root: target.root.is_some(),
            environment: target.environment.clone(),
            instance: target.instance.clone(),
            home,
            root,
            paths,
        })
    }

    pub fn vpnd(&self) -> PathBuf {
        self.bin.join("vpnd")
    }

    pub fn log(&self, component: Component) -> PathBuf {
        self.logs.join(format!("{}.log", component.name()))
    }

    /// The command line of a component. Every argument is one element, so paths with spaces need
    /// no quoting in a plist; the systemd unit quotes each.
    pub fn argv(
        &self,
        component: Component,
        listen: &Listen,
        ssh_dir: Option<&Path>,
    ) -> anyhow::Result<Vec<String>> {
        let mut argv = vec![
            check_path(&self.vpnd())?.to_owned(),
            component.name().to_owned(),
            "--log-file".to_owned(),
            check_path(&self.log(component))?.to_owned(),
        ];
        if self.custom_root {
            argv.extend(["--state-dir".to_owned(), check_path(&self.root)?.to_owned()]);
        }
        match component {
            Component::Manager => {
                if let Some(dir) = ssh_dir {
                    argv.extend(["--ssh-dir".to_owned(), check_path(dir)?.to_owned()]);
                }
                // Its systemd unit has `Delegate=yes`; systemd's user manager marks no cgroup as
                // delegated, so the manager is told.
                if cfg!(target_os = "linux") {
                    argv.push("--delegated-cgroup".to_owned());
                }
            }
            Component::Controller => {
                argv.extend(["--port".to_owned(), listen.port.to_string()]);
                // The default is not written: a loopback installation's definition stays as
                // it always was.
                if listen.address != Listen::DEFAULT_ADDRESS {
                    argv.extend(["--listen-address".to_owned(), listen.address.to_string()]);
                }
                for net in &listen.allow {
                    argv.extend(["--allow-client".to_owned(), net.to_string()]);
                }
            }
        }
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(&Target {
            root: Some(dir.path().to_path_buf()),
            environment: "test".into(),
            instance: "listen".into(),
        })
        .unwrap();
        (dir, layout)
    }

    #[test]
    fn the_controller_is_told_where_to_listen_and_for_whom() {
        let (_dir, layout) = layout();
        let lan = Listen {
            port: 18765,
            address: "0.0.0.0".parse().unwrap(),
            allow: vec![
                "192.168.10.0/24".parse().unwrap(),
                "192.168.20.0/24".parse().unwrap(),
            ],
        };
        let argv = layout.argv(Component::Controller, &lan, None).unwrap();
        let tail: Vec<&str> = argv
            .iter()
            .skip_while(|a| *a != "--port")
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--port",
                "18765",
                "--listen-address",
                "0.0.0.0",
                "--allow-client",
                "192.168.10.0/24",
                "--allow-client",
                "192.168.20.0/24"
            ]
        );
        // The manager does not listen anywhere: none of it.
        let manager = layout.argv(Component::Manager, &lan, None).unwrap();
        assert!(
            !manager
                .iter()
                .any(|a| a.starts_with("--listen") || a.starts_with("--allow"))
        );
        // The default writes nothing new: existing definitions stay byte for byte.
        let plain = layout
            .argv(Component::Controller, &Listen::loopback(18765), None)
            .unwrap();
        assert_eq!(plain.last().map(String::as_str), Some("18765"));
        assert!(
            !plain
                .iter()
                .any(|a| a.starts_with("--listen") || a.starts_with("--allow"))
        );
    }
}
