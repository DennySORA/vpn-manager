//! Read-only view of the user's `~/.ssh/config`: its host blocks and where our `Include` stands.
//! `Match` blocks and other `Include`s are not expanded; only what ssh would apply first matters.

use vpn_domain::{SshExistingHost, SshIncludeState};

/// Split one line into keyword and arguments the way ssh does.
///
/// That is an optional `=` after the keyword, single- or double-quoted arguments with backslash escapes, and a `#` that starts a
/// word (outside quotes) ends the line.
#[must_use]
pub fn tokenize(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut chars = line.chars().peekable();
    let mut keyword = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '=' {
            break;
        }
        keyword.push(c);
        chars.next();
    }
    while chars.peek().is_some_and(|c| c.is_whitespace()) {
        chars.next();
    }
    if chars.peek() == Some(&'=') {
        chars.next();
    }
    let mut args = Vec::new();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        match chars.peek() {
            None | Some('#') => break,
            _ => {}
        }
        let mut word = String::new();
        let mut quote: Option<char> = None;
        while let Some(&c) = chars.peek() {
            match quote {
                Some(q) if c == q => {
                    quote = None;
                    chars.next();
                }
                Some(_) if c == '\\' => {
                    chars.next();
                    if let Some(n) = chars.next() {
                        word.push(n);
                    }
                }
                None if c == '"' || c == '\'' => {
                    quote = Some(c);
                    chars.next();
                }
                None if c.is_whitespace() => break,
                // Inside quotes, and outside them, any other character is part of the word.
                Some(_) | None => {
                    word.push(c);
                    chars.next();
                }
            }
        }
        args.push(word);
    }
    Some((keyword.to_ascii_lowercase(), args))
}

/// What the user's configuration says, as far as the SSH Manager needs to know.
#[derive(Debug, Clone)]
pub struct UserConfig {
    pub hosts: Vec<SshExistingHost>,
    pub include: SshIncludeState,
}

impl UserConfig {
    /// The plain (wildcard-free) host block whose patterns contain `alias`, if any.
    #[must_use]
    pub fn host(&self, alias: &str) -> Option<&SshExistingHost> {
        self.hosts
            .iter()
            .find(|h| !h.wildcard && h.patterns.iter().any(|p| p == alias))
    }

    /// Whether any block's patterns name `alias` (an alias VPN Manager must not redefine).
    #[must_use]
    pub fn names(&self, alias: &str) -> bool {
        self.hosts
            .iter()
            .any(|h| h.patterns.iter().any(|p| p == alias))
    }
}

/// Parse `text`; `is_ours` recognizes an `Include` argument that loads our file.
pub fn parse(text: &str, is_ours: impl Fn(&str) -> bool) -> UserConfig {
    let mut hosts = Vec::new();
    let mut current: Option<SshExistingHost> = None;
    let mut in_block = false;
    let mut settings_before = false;
    let mut include = SshIncludeState::Missing;
    for (n, raw) in text.lines().enumerate() {
        let Some((keyword, args)) = tokenize(raw) else {
            continue;
        };
        match keyword.as_str() {
            "host" => {
                hosts.extend(current.take());
                current = Some(SshExistingHost {
                    wildcard: args
                        .iter()
                        .any(|p| p.contains(['*', '?']) || p.starts_with('!')),
                    patterns: args,
                    host_name: None,
                    user: None,
                    port: None,
                    proxied: false,
                    line: u32::try_from(n + 1).unwrap_or(u32::MAX),
                });
                in_block = true;
                settings_before = true;
            }
            "match" => {
                hosts.extend(current.take());
                in_block = true;
                settings_before = true;
            }
            "include" => {
                if include == SshIncludeState::Missing && args.iter().any(|a| is_ours(a)) {
                    include = if settings_before || in_block {
                        SshIncludeState::Late
                    } else {
                        SshIncludeState::Present
                    };
                }
                // Another file loaded first may set the same hosts first (its contents are not
                // read here), so ours is only in effect ahead of it.
                if !args.iter().all(|a| is_ours(a)) {
                    settings_before = true;
                }
            }
            other => {
                settings_before = true;
                let Some(h) = current.as_mut() else {
                    continue;
                };
                // ssh uses the first value it obtains.
                let first = args.first().cloned();
                match other {
                    "hostname" if h.host_name.is_none() => h.host_name = first,
                    "user" if h.user.is_none() => h.user = first,
                    "port" if h.port.is_none() => h.port = first.and_then(|p| p.parse().ok()),
                    "proxyjump" | "proxycommand" => {
                        h.proxied |= first.is_some_and(|v| !v.eq_ignore_ascii_case("none"));
                    }
                    _ => {}
                }
            }
        }
    }
    hosts.extend(current);
    UserConfig { hosts, include }
}
