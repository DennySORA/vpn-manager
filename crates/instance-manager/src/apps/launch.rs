//! What an App is started with: its arguments (placeholders replaced) and its environment.
//! Pure functions: the supervisor resolves the facts, these turn them into a command.

use std::collections::BTreeMap;

use vpn_domain::{
    APP_PLACEHOLDER_GATEWAY_PORT, APP_PLACEHOLDER_HOME, APP_RESERVED_ENV, AppClass, AppIsolation,
    EnvVar, GatewayId, GatewayKind, InstanceId,
};

/// The Gateway a run points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayTarget {
    pub instance_id: InstanceId,
    pub id: GatewayId,
    pub port: u16,
    pub kind: GatewayKind,
}

/// `PATH` when the App's own list does not set one.
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Replace `{gateway_port}` (when there is a Gateway) and `{app_home}` in one pass; nothing else
/// is touched, and replaced text is never scanned again.
pub fn substitute(arg: &str, gateway_port: Option<u16>, home: &str) -> String {
    let port = gateway_port.map(|p| p.to_string());
    let mut out = String::with_capacity(arg.len() + home.len());
    let mut rest = arg;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let (Some(p), Some(after)) = (
            port.as_deref(),
            tail.strip_prefix(APP_PLACEHOLDER_GATEWAY_PORT),
        ) {
            out.push_str(p);
            rest = after;
        } else if let Some(after) = tail.strip_prefix(APP_PLACEHOLDER_HOME) {
            out.push_str(home);
            rest = after;
        } else {
            out.push('{');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// The App's arguments as started: what its class puts first (a browser's data directory of its
/// own, so a copy the user already runs is never reused), then its own; placeholders replaced in
/// each, once.
pub fn arguments(
    class: Option<AppClass>,
    args: &[String],
    gateway_port: Option<u16>,
    home: &str,
) -> Vec<String> {
    let first: &[&str] = class.map_or_default(AppClass::launch_args);
    first
        .iter()
        .map(|a| substitute(a, gateway_port, home))
        .chain(args.iter().map(|a| substitute(a, gateway_port, home)))
        .collect()
}

/// The facts the environment is built from.
pub struct EnvFacts<'a> {
    pub spec_env: &'a [EnvVar],
    pub isolation: AppIsolation,
    pub gateway: Option<GatewayTarget>,
    pub home: &'a str,
    pub tmp: &'a str,
    /// Login name for `USER` / `LOGNAME`.
    pub user: Option<&'a str>,
    /// The run, as `VPNM_RUN`.
    pub run_id: &'a str,
}

/// The App's whole environment (nothing is inherited from VPN Manager): defaults, then the
/// App's own variables, then what VPN Manager sets and the App cannot override — the run's
/// `VPNM_RUN`, its private `HOME`/`TMPDIR` and, for the proxy modes, the proxy variables matching
/// the Gateway's kind
/// (SOCKS through `socks5h` so names resolve in the tunnel, HTTP for HTTP-capable Gateways) with
/// an empty `NO_PROXY`.
pub fn environment(f: &EnvFacts<'_>) -> Vec<(String, String)> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    env.insert("PATH".into(), DEFAULT_PATH.into());
    if let Some(user) = f.user {
        env.insert("USER".into(), user.into());
        env.insert("LOGNAME".into(), user.into());
    }
    for e in f.spec_env {
        if !APP_RESERVED_ENV.contains(&e.name.as_str()) {
            env.insert(e.name.clone(), e.value.clone());
        }
    }
    env.insert(vpn_platform::apps::proc::RUN_ENV.into(), f.run_id.into());
    env.insert("HOME".into(), f.home.into());
    env.insert("TMPDIR".into(), f.tmp.into());
    let proxied = matches!(
        f.isolation,
        AppIsolation::ProxyEnv | AppIsolation::EnforcedProxy
    );
    if let Some(g) = f.gateway.filter(|_| proxied) {
        if matches!(g.kind, GatewayKind::Socks5 | GatewayKind::Mixed) {
            let socks = format!("socks5h://127.0.0.1:{}", g.port);
            env.insert("ALL_PROXY".into(), socks.clone());
            env.insert("all_proxy".into(), socks);
        }
        if matches!(g.kind, GatewayKind::Http | GatewayKind::Mixed) {
            let http = format!("http://127.0.0.1:{}", g.port);
            for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
                env.insert(k.into(), http.clone());
            }
        }
        env.insert("NO_PROXY".into(), String::new());
        env.insert("no_proxy".into(), String::new());
    }
    env.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw(kind: GatewayKind) -> GatewayTarget {
        GatewayTarget {
            instance_id: InstanceId::new(),
            id: GatewayId::new(),
            port: 29210,
            kind,
        }
    }

    #[test]
    fn a_browser_starts_with_a_data_directory_in_its_own_home() {
        let home = "/data/apps/a/home";
        let args = ["https://example.com".to_string()];
        assert_eq!(
            arguments(Some(AppClass::Chromium), &args, Some(1080), home),
            [
                "--user-data-dir=/data/apps/a/home/chromium-data",
                "https://example.com"
            ]
        );
        assert_eq!(
            arguments(Some(AppClass::Firefox), &args, None, home),
            [
                "-profile",
                "/data/apps/a/home/firefox-profile",
                "-no-remote",
                "-new-instance",
                "https://example.com"
            ]
        );
        // Nothing to add for other programs; their own arguments as given.
        for class in [None, Some(AppClass::Gui), Some(AppClass::Launcher)] {
            assert_eq!(
                arguments(
                    class,
                    &["-a".into(), "{gateway_port}".into()],
                    Some(7),
                    home
                ),
                ["-a", "7"]
            );
        }
    }

    fn env_of(
        isolation: AppIsolation,
        gateway: Option<GatewayTarget>,
        spec: &[EnvVar],
    ) -> BTreeMap<String, String> {
        environment(&EnvFacts {
            spec_env: spec,
            isolation,
            gateway,
            home: "/h",
            tmp: "/t",
            user: Some("me"),
            run_id: "r1",
        })
        .into_iter()
        .collect()
    }

    #[test]
    fn the_app_cannot_override_what_vpn_manager_sets() {
        let spec = [
            EnvVar {
                name: "ALL_PROXY".into(),
                value: "socks5://evil:1".into(),
            },
            EnvVar {
                name: "HOME".into(),
                value: "/Users/me".into(),
            },
            EnvVar {
                name: "PATH".into(),
                value: "/opt/bin:/usr/bin".into(),
            },
            EnvVar {
                name: "LANG".into(),
                value: "zh_TW.UTF-8".into(),
            },
            EnvVar {
                name: "VPNM_RUN".into(),
                value: "another".into(),
            },
        ];
        let env = env_of(AppIsolation::ProxyEnv, Some(gw(GatewayKind::Mixed)), &spec);
        assert_eq!(env["ALL_PROXY"], "socks5h://127.0.0.1:29210");
        assert_eq!(env["HOME"], "/h");
        assert_eq!(env["TMPDIR"], "/t");
        assert_eq!(env["VPNM_RUN"], "r1");
        // The App's own variables otherwise win over the defaults.
        assert_eq!(env["PATH"], "/opt/bin:/usr/bin");
        assert_eq!(env["LANG"], "zh_TW.UTF-8");
        assert_eq!(env["USER"], "me");
        // Nothing of VPN Manager's own environment leaks in.
        assert!(!env.contains_key("RUST_LOG") && !env.contains_key("CARGO"));
        assert_eq!(
            env_of(AppIsolation::ProxyEnv, None, &[])["PATH"],
            DEFAULT_PATH
        );
    }
}
