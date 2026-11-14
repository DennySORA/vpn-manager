//! Linux: systemd user units in `$XDG_CONFIG_HOME/systemd/user` (`~/.config/systemd/user`) — no
//! root. Enabled into `default.target`; with lingering the user manager starts at boot and keeps
//! the services after logout, so the installer turns lingering on when it is off (and says so;
//! `loginctl disable-linger` turns it off again). The programs write their own logs; nothing
//! goes to the journal.
//!
//! Restarts follow launchd's pace: soon after a crash of a service that had been running, every
//! 10 s at most in a crash loop — with systemd 254 or later through `RestartSteps` (1 s growing
//! to 10 s), on older versions a fixed 5 s.

use std::path::{Path, PathBuf};
use std::process::Output;

use anyhow::bail;

use crate::layout::{Component, Job, Layout};
use crate::supervisor::{
    JobState, RESTART_DELAY_SECS, Supervisor, expect_ok, run, stop_timeout_secs, user_name,
};

pub struct Systemd {
    units: PathBuf,
    /// Major version of the user manager (`systemctl --version`), 0 when unknown.
    version: u32,
}

/// The first version that knows `RestartSteps=` and `RestartMaxDelaySec=`.
const BACKOFF_SINCE: u32 = 254;

impl Systemd {
    pub fn new(home: &Path) -> anyhow::Result<Self> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        // The user manager must answer: a login session, or lingering.
        let reachable =
            run("systemctl", &["--user", "show-environment"]).is_ok_and(|o| o.status.success());
        if !reachable {
            bail!(
                "連不到 systemd 使用者服務管理員（systemctl --user）：請在使用者自己的登入工作階段執行，或先讓系統管理員執行 loginctl enable-linger {}",
                user_name().unwrap_or_else(|_| "<使用者>".into())
            );
        }
        let version = run("systemctl", &["--version"])
            .ok()
            .and_then(|o| parse_version(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or(0);
        Ok(Self {
            units: config.join("systemd/user"),
            version,
        })
    }

    fn systemctl(args: &[&str]) -> anyhow::Result<Output> {
        let mut all = vec!["--user"];
        all.extend_from_slice(args);
        run("systemctl", &all)
    }

    fn show(job: &Job) -> anyhow::Result<Vec<(String, String)>> {
        let out = Self::systemctl(&[
            "show",
            &job.name,
            "--property=LoadState,ActiveState,SubState,MainPID,NRestarts,ExecMainCode,ExecMainStatus,UnitFileState",
        ])?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect())
    }
}

fn prop<'a>(props: &'a [(String, String)], key: &str) -> &'a str {
    props
        .iter()
        .find(|(k, _)| k == key)
        .map_or("", |(_, v)| v.as_str())
}

impl Supervisor for Systemd {
    fn kind(&self) -> &'static str {
        "systemd"
    }

    fn job(&self, layout: &Layout, component: Component) -> Job {
        let name = format!(
            "ops.vpn-manager.{}.{}.{}.service",
            component.name(),
            layout.environment,
            layout.instance
        );
        Job {
            component,
            definition: self.units.join(&name),
            log: layout.log(component),
            name,
        }
    }

    fn render(&self, job: &Job, argv: &[String], working_dir: &str) -> String {
        unit(job, argv, working_dir, self.version)
    }

    fn validate(&self, staged: &Path) -> anyhow::Result<()> {
        let Some(path) = staged.to_str() else {
            bail!("unit path is not UTF-8");
        };
        // Not every system ships systemd-analyze; systemd still checks the unit on load.
        run("systemd-analyze", &["--user", "verify", path])
            .map_or(Ok(()), |out| expect_ok(&out, "systemd-analyze verify"))
    }

    fn state(&self, job: &Job) -> anyhow::Result<JobState> {
        let p = Self::show(job)?;
        let loaded = prop(&p, "LoadState") == "loaded";
        if !loaded {
            return Ok(JobState {
                loaded,
                running: false,
                summary: format!("未載入（{}）", prop(&p, "LoadState")),
            });
        }
        let (active, sub) = (prop(&p, "ActiveState"), prop(&p, "SubState"));
        let last = match (prop(&p, "ExecMainCode"), prop(&p, "ExecMainStatus")) {
            ("0" | "", _) => "尚未結束過".to_owned(),
            // CLD_EXITED = 1; otherwise a signal number.
            ("1", status) => format!("結束碼 {status}"),
            (_, status) => format!("訊號 {status}"),
        };
        Ok(JobState {
            loaded,
            running: active == "active" && sub == "running",
            summary: format!(
                "{active}（{sub}），pid {}，重新啟動 {} 次，上次結束：{last}，開機啟動：{}",
                prop(&p, "MainPID"),
                prop(&p, "NRestarts"),
                prop(&p, "UnitFileState"),
            ),
        })
    }

    fn stop(&self, job: &Job) -> anyhow::Result<()> {
        let p = Self::show(job)?;
        if prop(&p, "LoadState") != "loaded" || prop(&p, "ActiveState") == "inactive" {
            return Ok(());
        }
        // Blocks until the unit stopped (SIGTERM, then SIGKILL after TimeoutStopSec).
        expect_ok(
            &Self::systemctl(&["stop", &job.name])?,
            "systemctl --user stop",
        )?;
        // Read it back: only a unit systemd reports inactive (or failed) counts as stopped.
        let p = Self::show(job)?;
        match prop(&p, "ActiveState") {
            "inactive" | "failed" => Ok(()),
            other => bail!("{} 沒有停止（ActiveState={other}）", job.name),
        }
    }

    fn start(&self, jobs: &[Job]) -> anyhow::Result<()> {
        expect_ok(
            &Self::systemctl(&["daemon-reload"])?,
            "systemctl --user daemon-reload",
        )?;
        for job in jobs {
            expect_ok(
                &Self::systemctl(&["enable", &job.name])?,
                "systemctl --user enable",
            )?;
        }
        for job in jobs {
            expect_ok(
                &Self::systemctl(&["start", &job.name])?,
                "systemctl --user start",
            )?;
        }
        Ok(())
    }

    fn remove(&self, jobs: &[Job]) -> anyhow::Result<()> {
        for job in jobs {
            self.stop(job)?;
            if job.definition.exists() {
                expect_ok(
                    &Self::systemctl(&["disable", &job.name])?,
                    "systemctl --user disable",
                )?;
            }
            crate::fsx::remove_if_present(&job.definition)?;
        }
        expect_ok(
            &Self::systemctl(&["daemon-reload"])?,
            "systemctl --user daemon-reload",
        )?;
        for job in jobs {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "clears a failed state left behind; nothing to clear, or no answer, is fine"
            )]
            let _ = Self::systemctl(&["reset-failed", &job.name]);
        }
        Ok(())
    }

    fn ensure_unattended(&self) -> anyhow::Result<bool> {
        let user = user_name()?;
        let out = run(
            "loginctl",
            &["show-user", &user, "--property=Linger", "--value"],
        )?;
        if String::from_utf8_lossy(&out.stdout).trim() == "yes" {
            return Ok(false);
        }
        expect_ok(
            &run("loginctl", &["enable-linger", &user])?,
            "loginctl enable-linger",
        )?;
        Ok(true)
    }
}

fn unit(job: &Job, argv: &[String], working_dir: &str, version: u32) -> String {
    let what = match job.component {
        Component::Manager => "core (Instance Manager, Store)",
        Component::Controller => "web UI and API",
    };
    let exec = argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
    // The manager gives its workers and managed Apps cgroups of their own below the unit's
    // (memory, CPU and process limits): systemd leaves that subtree to it. Stopping it signals
    // the manager alone first (`mixed`): it ends its Apps itself and keeps their run records,
    // so the next start brings back those set to restart. Signalled together with the manager,
    // an App could end first, look like it exited on its own, and stay stopped after an
    // upgrade or a reboot. Whatever is left when the manager exits is killed by systemd.
    let delegate = match job.component {
        Component::Manager => "Delegate=yes\nKillMode=mixed\n",
        Component::Controller => "",
    };
    let restart = if version >= BACKOFF_SINCE {
        format!("RestartSec=1s\nRestartSteps=4\nRestartMaxDelaySec={RESTART_DELAY_SECS}s")
    } else {
        "RestartSec=5s".to_owned()
    };
    format!(
        "# Generated by vpn-installer; run it again to change this unit.
[Unit]
Description=VPN Manager {what}
# Keep trying, like launchd: a crash loop costs at most one start every few seconds.
StartLimitIntervalSec=0

[Service]
Type=exec
ExecStart={exec}
WorkingDirectory={dir}
Restart=on-failure
{restart}
TimeoutStopSec={stop}s
StandardInput=null
StandardOutput=null
StandardError=null
UMask=0077
NoNewPrivileges=yes
{delegate}
[Install]
WantedBy=default.target
",
        dir = specifiers(working_dir),
        stop = stop_timeout_secs(job.component),
    )
}

/// `systemd 257 (257.13-1~deb13u1)` → 257.
fn parse_version(text: &str) -> Option<u32> {
    text.lines()
        .next()?
        .strip_prefix("systemd ")?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// One `ExecStart=` argument: double-quoted, with the escapes systemd's parser and its `%`
/// specifiers and `$` variables need.
fn quote(arg: &str) -> String {
    let mut s = String::with_capacity(arg.len() + 2);
    s.push('"');
    for c in arg.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '%' => s.push_str("%%"),
            '$' => s.push_str("$$"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

fn specifiers(value: &str) -> String {
    value.replace('%', "%%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_controllers_unit_carries_where_it_listens_and_for_whom() {
        let job = Job {
            component: Component::Controller,
            name: "ops.vpn-manager.controller.prod.main.service".into(),
            definition: PathBuf::from("/x"),
            log: PathBuf::from("/x.log"),
        };
        let argv: Vec<String> = [
            "/home/u/.local/share/vpn-manager/bin/vpnd",
            "controller",
            "--port",
            "18765",
            "--listen-address",
            "0.0.0.0",
            "--allow-client",
            "192.168.10.0/24",
            "--allow-client",
            "192.168.20.0/24",
        ]
        .map(String::from)
        .into();
        let text = unit(&job, &argv, "/home/u/.local/share/vpn-manager", 257);
        assert!(
            text.contains(
                "\"--port\" \"18765\" \"--listen-address\" \"0.0.0.0\" \"--allow-client\" \"192.168.10.0/24\" \"--allow-client\" \"192.168.20.0/24\"\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn exec_arguments_survive_systemd_quoting() {
        assert_eq!(quote("/home/a b/vpnd"), "\"/home/a b/vpnd\"");
        assert_eq!(quote(r#"x"y\z"#), r#""x\"y\\z""#);
        assert_eq!(quote("50%$HOME"), "\"50%%$$HOME\"");
        let job = Job {
            component: Component::Controller,
            name: "ops.vpn-manager.controller.prod.main.service".into(),
            definition: PathBuf::from("/x"),
            log: PathBuf::from("/x.log"),
        };
        let argv: Vec<String> = [
            "/home/u/.local/share/vpn-manager/bin/vpnd",
            "controller",
            "--port",
            "18765",
        ]
        .map(String::from)
        .into();
        let text = unit(&job, &argv, "/home/u/.local/share/vpn-manager", 257);
        assert!(text.contains(
            "ExecStart=\"/home/u/.local/share/vpn-manager/bin/vpnd\" \"controller\" \"--port\" \"18765\"\n"
        ));
        assert!(text.contains("Restart=on-failure\n"));
        // Every non-zero exit is a failure, the manager watchdog's 76 included: nothing exempts
        // an exit status from the restart.
        assert!(
            !text.contains("SuccessExitStatus=") && !text.contains("RestartPreventExitStatus=")
        );
        assert!(text.contains("RestartSteps=4\n"));
        assert!(text.contains("WantedBy=default.target\n"));
        assert!(unit(&job, &argv, "/x", 252).contains("RestartSec=5s\n"));
        assert!(
            !text.contains("Delegate="),
            "the controller starts no children"
        );
        let manager = Job {
            component: Component::Manager,
            ..job
        };
        let text = unit(&manager, &argv, "/x", 257);
        assert!(text.contains("\nDelegate=yes\n"));
        assert!(
            text.contains("\nKillMode=mixed\n"),
            "a stop reaches the manager first, which ends its Apps keeping their run records"
        );
        assert_eq!(
            parse_version("systemd 257 (257.13-1~deb13u1)\n+PAM"),
            Some(257)
        );
        assert_eq!(parse_version("systemd 252\n"), Some(252));
    }
}
