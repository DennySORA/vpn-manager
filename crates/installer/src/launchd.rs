//! macOS: per-user `LaunchAgents` in the `gui/<uid>` domain, `~/Library/LaunchAgents/<label>.plist`
//! — no root, native supervision, started at login. Loaded with `launchctl bootstrap` and
//! unloaded with `bootout`; never `load`/`unload`, which report success for nearly every failure.
//! The manager is `Interactive`: its workers carry the traffic of every app on a Gateway, and the
//! default class is throttled. The controller only serves the workbench (`Standard`). No log path
//! is given to launchd: a path whose directory is gone keeps a job from starting, so the programs
//! write their own logs (`--log-file`).

#![expect(unsafe_code, reason = "getuid for the gui/<uid> launchd domain")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};

use crate::layout::{Component, Job, Layout};
use crate::supervisor::{
    JobState, RESTART_DELAY_SECS, Supervisor, expect_ok, run, stop_timeout_secs,
};

const LABEL_PREFIX: &str = "io.dennysora.ops.vpn-manager";
const LAUNCHCTL: &str = "/bin/launchctl";
const PLUTIL: &str = "/usr/bin/plutil";

pub struct Launchd {
    domain: String,
    agents: PathBuf,
}

impl Launchd {
    pub fn new(home: &Path) -> Self {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        Self {
            domain: format!("gui/{uid}"),
            agents: home.join("Library/LaunchAgents"),
        }
    }

    fn target(&self, job: &Job) -> String {
        format!("{}/{}", self.domain, job.name)
    }

    /// `launchctl print` of a loaded job; `None` when it is not loaded.
    fn print(&self, job: &Job) -> anyhow::Result<Option<String>> {
        let out = run(LAUNCHCTL, &["print", &self.target(job)])?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.success() {
            return Ok(Some(stdout));
        }
        let text = String::from_utf8_lossy(&out.stderr).into_owned() + &stdout;
        if text.contains("Could not find service") {
            return Ok(None);
        }
        bail!("launchctl print {} 失敗：{}", job.name, text.trim())
    }

    fn disabled(&self, job: &Job) -> anyhow::Result<bool> {
        let out = run(LAUNCHCTL, &["print-disabled", &self.domain])?;
        let text = String::from_utf8_lossy(&out.stdout);
        let key = format!("\"{}\" => ", job.name);
        // macOS 26 writes enabled/disabled; older releases true (disabled) or false.
        Ok(text.lines().any(|l| {
            l.trim_start()
                .strip_prefix(&key)
                .is_some_and(|v| matches!(v.trim(), "disabled" | "true"))
        }))
    }
}

impl Supervisor for Launchd {
    fn kind(&self) -> &'static str {
        "launchd"
    }

    fn job(&self, layout: &Layout, component: Component) -> Job {
        let name = format!(
            "{LABEL_PREFIX}.{}.{}.{}",
            component.name(),
            layout.environment,
            layout.instance
        );
        Job {
            component,
            definition: self.agents.join(format!("{name}.plist")),
            log: layout.log(component),
            name,
        }
    }

    fn render(&self, job: &Job, argv: &[String], working_dir: &str) -> String {
        plist(job, argv, working_dir)
    }

    fn validate(&self, staged: &Path) -> anyhow::Result<()> {
        let path = staged.to_str().context("plist path is not UTF-8")?;
        expect_ok(&run(PLUTIL, &["-lint", path])?, "plutil -lint")
    }

    fn state(&self, job: &Job) -> anyhow::Result<JobState> {
        let Some(p) = self.print(job)? else {
            return Ok(JobState {
                loaded: false,
                running: false,
                summary: "未載入".into(),
            });
        };
        let state = field(&p, "state").unwrap_or("?");
        // After a signal launchd reports the signal instead of an exit code.
        let last = match field(&p, "last exit code") {
            Some("(never exited)") => "尚未結束過".to_owned(),
            Some(code) => format!("結束碼 {code}"),
            None => field(&p, "last terminating signal")
                .map_or_else(|| "—".to_owned(), |s| format!("訊號 {s}")),
        };
        Ok(JobState {
            loaded: true,
            running: state == "running",
            summary: format!(
                "{state}，pid {}，已啟動 {} 次，上次結束：{last}",
                field(&p, "pid").unwrap_or("-"),
                field(&p, "runs").unwrap_or("?"),
            ),
        })
    }

    fn stop(&self, job: &Job) -> anyhow::Result<()> {
        if self.print(job)?.is_none() {
            return Ok(());
        }
        let out = run(LAUNCHCTL, &["bootout", &self.target(job)])?;
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        // launchd sends SIGTERM, then SIGKILL after ExitTimeOut.
        let end = Instant::now() + Duration::from_secs(stop_timeout_secs(job.component) + 10);
        while self.print(job)?.is_some() {
            if Instant::now() >= end {
                bail!("{} 沒有停止：{detail}", job.name);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    fn start(&self, jobs: &[Job]) -> anyhow::Result<()> {
        for job in jobs {
            // Still loaded (a stop that failed): leave it; the readiness check tells.
            if self.print(job)?.is_some() {
                continue;
            }
            // A disabled label does not load; enabling neither starts nor stops anything.
            if self.disabled(job)? {
                expect_ok(
                    &run(LAUNCHCTL, &["enable", &self.target(job)])?,
                    "launchctl enable",
                )?;
            }
            let plist = job.definition.to_str().context("plist path is not UTF-8")?;
            expect_ok(
                &run(LAUNCHCTL, &["bootstrap", &self.domain, plist])?,
                "launchctl bootstrap",
            )
            .with_context(|| job.name.clone())?;
        }
        Ok(())
    }

    fn remove(&self, jobs: &[Job]) -> anyhow::Result<()> {
        for job in jobs {
            self.stop(job)?;
            crate::fsx::remove_if_present(&job.definition)?;
        }
        Ok(())
    }

    fn ensure_unattended(&self) -> anyhow::Result<bool> {
        // LaunchAgents start with the user's login; nothing else to arrange.
        Ok(false)
    }
}

fn plist(job: &Job, argv: &[String], working_dir: &str) -> String {
    let arg_lines = argv.iter().fold(String::new(), |mut out, a| {
        out.push_str("\t\t<string>");
        out.push_str(&xml(a));
        out.push_str("</string>\n");
        out
    });
    let process_type = match job.component {
        Component::Manager => "Interactive",
        Component::Controller => "Standard",
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
{arg_lines}	</array>
	<key>WorkingDirectory</key>
	<string>{working_dir}</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>{RESTART_DELAY_SECS}</integer>
	<key>ExitTimeOut</key>
	<integer>{stop}</integer>
	<key>ProcessType</key>
	<string>{process_type}</string>
</dict>
</plist>
"#,
        label = xml(&job.name),
        working_dir = xml(working_dir),
        stop = stop_timeout_secs(job.component),
    )
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One top-level `key = value` line of `launchctl print` — diagnostic text whose layout Apple
/// does not promise, so only single values are read from it.
fn field<'a>(print: &'a str, key: &str) -> Option<&'a str> {
    print
        .lines()
        .find_map(|l| l.strip_prefix('\t')?.strip_prefix(key)?.strip_prefix(" = "))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_controllers_plist_carries_where_it_listens_and_for_whom() {
        let job = Job {
            component: Component::Controller,
            name: "io.dennysora.ops.vpn-manager.controller.prod.main".into(),
            definition: PathBuf::from("/x.plist"),
            log: PathBuf::from("/x.log"),
        };
        let argv: Vec<String> = [
            "/Users/x/Library/Application Support/VPN Manager/bin/vpnd",
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
        let text = plist(
            &job,
            &argv,
            "/Users/x/Library/Application Support/VPN Manager",
        );
        assert!(text.contains(
            "\t\t<string>--listen-address</string>\n\t\t<string>0.0.0.0</string>\n\t\t<string>--allow-client</string>\n\t\t<string>192.168.10.0/24</string>\n\t\t<string>--allow-client</string>\n\t\t<string>192.168.20.0/24</string>\n"
        ), "{text}");
    }

    /// The plist is valid for `plutil`, and the argument vector comes back exactly — spaces and
    /// markup characters included.
    #[cfg(target_os = "macos")]
    #[test]
    fn plist_round_trips_the_argument_vector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.plist");
        let argv: Vec<String> = [
            "/Users/x/Library/Application Support/VPN Manager/bin/vpnd",
            "manager",
            "--log-file",
            "/Users/x/Library/Application Support/VPN Manager/logs/a&b <c>.log",
        ]
        .map(String::from)
        .into();
        let job = Job {
            component: Component::Manager,
            name: "io.dennysora.ops.vpn-manager.manager.test.check".into(),
            definition: path.clone(),
            log: PathBuf::from("/tmp/x.log"),
        };
        std::fs::write(
            &path,
            plist(
                &job,
                &argv,
                "/Users/x/Library/Application Support/VPN Manager",
            ),
        )
        .unwrap();
        let launchd = Launchd::new(Path::new("/Users/x"));
        launchd.validate(&path).unwrap();
        let out = std::process::Command::new(PLUTIL)
            .args(["-extract", "ProgramArguments", "json", "-o", "-"])
            .arg(&path)
            .output()
            .unwrap();
        let back: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(back, argv);
    }
}
