// SPDX-License-Identifier: GPL-3.0-or-later

//! A fake airvpn.org for the website client: the sign-in (`/login/`) and the Ports page
//! (`/ports/`) as observed on 2026-11-02, with sessions in cookies, the page token in the
//! escaped `data-json`, and the page's port calls — list, reserve, delete, the seven settings,
//! the sessions of a port and their test, the DDNS check and the search for free ports.
//! Transport-free (std only): each test harness hands it requests and serves its answers — the
//! providers crate over its in-memory TLS fixture, the controller behind its relay and egress
//! guard.
//!
//! Knobs make it misbehave the ways the client must survive: a session that dies mid-way, a
//! CAPTCHA, a second factor, a changed form, a locked sign-in, an odd page after signing in, a
//! garbled or refusing answer to a reservation, a setting refused, ignored or answered with a
//! page, a test refused, garbled or never answered.

#![cfg(test)]
#![expect(dead_code, reason = "each test binary uses a different part")]

use std::collections::HashMap;
use std::sync::Mutex;

pub const LOGIN_PAGE: &str = include_str!("../fixtures/airvpn/site/login.html");
pub const PORTS_SIGNED_OUT: &str = include_str!("../fixtures/airvpn/site/ports-signed-out.html");
/// The fixture's guest `csrfKey`, replaced by each session's own.
const FIXTURE_CSRF: &str = "0123456789abcdef0123456789abcdef";
/// The account's one device (`keys`): 50 hex digits like `AirVPN`'s.
pub const DEVICE_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a697887";

/// How a signed-out port call is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignedOut {
    /// The Ports page itself ("Login required.", `X-IPS-LoggedIn: 0`).
    Page,
    /// A JSON error and no IPS header.
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginPage {
    Normal,
    /// A CAPTCHA inside the sign-in form.
    Captcha,
    /// The form lost its `csrfKey`.
    NoCsrf,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterLogin {
    /// Success: a redirect home (the right password).
    Redirect,
    /// The right password, then a second-factor form.
    SecondFactor,
    /// The right password, then a page that is neither (signed out, no form).
    Unexpected,
    /// Locked out, whatever the password.
    Locked,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Insert {
    Normal,
    /// The port is reserved but the answer is not JSON.
    GarbledButDone,
    /// Not reserved; `{"error": …}`.
    Refuse(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortsPage {
    Normal,
    /// Signed in, but no `air_data` element.
    NoAirData,
}

/// How a settings change (`edit_*`) is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edit {
    Normal,
    /// `{"error": message}` for this action; nothing changes.
    Refuse(&'static str, &'static str),
    /// Answered as saved (`{}`) for this action, yet nothing changes.
    Ignore(&'static str),
    /// Saved, but answered with a page.
    Garbled,
}

/// How a test (`action=test`) is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    /// `{"type": word, "message": text}`.
    Verdict(&'static str, &'static str),
    /// `{"error": text}`.
    Refuse(&'static str),
    /// A page instead of JSON.
    Garbled,
    /// Never answered.
    Stall,
}

/// A connected session of the account: it uses every enabled port of the account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FakeSession {
    pub protocol: &'static str,
    pub iplayer: &'static str,
    pub server_ip: &'static str,
}

#[derive(Clone, Debug)]
pub struct Knobs {
    pub login_page: LoginPage,
    pub after_login: AfterLogin,
    pub signed_out: SignedOut,
    /// The member session ends after this many port calls (once).
    pub expire_after_calls: Option<usize>,
    /// Every port call is answered as signed out.
    pub refuse_every_call: bool,
    pub insert: Insert,
    pub ports_page: PortsPage,
    pub edit: Edit,
    /// The account's connected sessions.
    pub sessions: Vec<FakeSession>,
    pub probe: Probe,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            login_page: LoginPage::Normal,
            after_login: AfterLogin::Redirect,
            signed_out: SignedOut::Page,
            expire_after_calls: None,
            refuse_every_call: false,
            insert: Insert::Normal,
            ports_page: PortsPage::Normal,
            edit: Edit::Normal,
            sessions: Vec::new(),
            probe: Probe::Verdict("ok", "Port is open: the program answered."),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakePort {
    pub port: u16,
    pub pool: u32,
    pub notes: String,
    pub enabled: bool,
    /// `all` or a device key id.
    pub device: String,
    pub protocol: String,
    /// The page's words: `both`, `v4`, `v6`.
    pub iplayer: String,
    pub local: u16,
    pub dns: String,
}

impl FakePort {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            pool: 2,
            notes: String::new(),
            enabled: true,
            device: "all".into(),
            protocol: "both".into(),
            iplayer: "both".into(),
            local: port,
            dns: String::new(),
        }
    }
}

struct Session {
    member: bool,
    csrf: String,
    token: String,
    calls: usize,
}

pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Never answered (the harness keeps the connection waiting).
    pub stall: bool,
}

impl Answer {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            stall: false,
        }
    }

    fn error(message: &str) -> Self {
        Self::new(200, format!(r#"{{"error":"{message}"}}"#)).json()
    }

    fn with(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn html(self) -> Self {
        self.with("content-type", "text/html;charset=UTF-8")
    }

    fn json(self) -> Self {
        self.with("content-type", "application/json")
    }

    fn signed_in(self, member: bool) -> Self {
        self.with("x-ips-loggedin", if member { "1" } else { "0" })
    }
}

/// One request as a harness hands it over.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub header: &'a dyn Fn(&str) -> Option<String>,
    pub body: &'a [u8],
}

#[derive(Default)]
pub struct State {
    sessions: HashMap<String, Session>,
    next: u64,
    next_random: u16,
    pub ports: Vec<FakePort>,
    pub knobs: Knobs,
    /// Every request: `GET /login/`, `POST /ports/ manifest`, …
    pub log: Vec<String>,
    /// Successful sign-ins.
    pub sign_ins: usize,
    /// The fields of each posted sign-in form, in order (they hold the password).
    pub login_forms: Vec<Vec<(String, String)>>,
    /// A port call missing a header the page's XHR sends, or a field the page's script sends.
    pub bad_xhr: Vec<String>,
    /// The fields of every port call in order, the page token left out.
    pub calls: Vec<Vec<(String, String)>>,
    /// Cookie values and page tokens handed out: none may ever show up anywhere else.
    pub issued: Vec<String>,
}

pub struct FakeSite {
    pub username: String,
    pub password: String,
    pub state: Mutex<State>,
}

impl FakeSite {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            state: Mutex::new(State {
                next_random: 35786,
                ..State::default()
            }),
        }
    }

    pub fn with_ports(self, ports: &[u16]) -> Self {
        self.state.lock().unwrap().ports = ports.iter().map(|&port| FakePort::new(port)).collect();
        self
    }

    pub fn knobs(&self, f: impl FnOnce(&mut Knobs)) {
        f(&mut self.state.lock().unwrap().knobs);
    }

    /// Change a reserved port as if on the website.
    pub fn port(&self, port: u16, f: impl FnOnce(&mut FakePort)) {
        let mut s = self.state.lock().unwrap();
        f(s.ports.iter_mut().find(|p| p.port == port).unwrap());
    }

    /// A reserved port as the site holds it.
    pub fn held(&self, port: u16) -> FakePort {
        let s = self.state.lock().unwrap();
        s.ports.iter().find(|p| p.port == port).unwrap().clone()
    }

    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    /// The port calls with `action`: each one's fields in order, the page token left out.
    pub fn calls(&self, action: &str) -> Vec<Vec<(String, String)>> {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.first().is_some_and(|(n, v)| n == "action" && v == action))
            .cloned()
            .collect()
    }

    /// Fields the page's script would have sent differently.
    pub fn bad_xhr(&self) -> Vec<String> {
        self.state.lock().unwrap().bad_xhr.clone()
    }

    pub fn sign_ins(&self) -> usize {
        self.state.lock().unwrap().sign_ins
    }

    pub fn ports(&self) -> Vec<u16> {
        self.state
            .lock()
            .unwrap()
            .ports
            .iter()
            .map(|p| p.port)
            .collect()
    }

    /// End every session now (the site signed everyone out).
    pub fn expire_all(&self) {
        self.state.lock().unwrap().sessions.clear();
    }

    /// Everything that must never leave the client: the credential, the cookies and tokens the
    /// site issued.
    pub fn secrets(&self) -> Vec<String> {
        let mut all = vec![self.username.clone(), self.password.clone()];
        all.extend(self.state.lock().unwrap().issued.iter().cloned());
        all
    }

    pub fn handle(&self, r: &Request<'_>) -> Answer {
        let mut s = self.state.lock().unwrap();
        let cookie = (r.header)("cookie").unwrap_or_default();
        let sid = cookie
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(n, _)| *n == "PHPSESSID")
            .map(|(_, v)| v.to_owned())
            .filter(|id| s.sessions.contains_key(id));
        let mut set = Vec::new();
        let sid = sid.unwrap_or_else(|| {
            let id = s.new_session();
            set.push(format!("PHPSESSID={id}; path=/; secure; HttpOnly"));
            set.push("ips4_noCache=1; path=/; secure; HttpOnly".to_owned());
            id
        });
        let form = decode_form(r.body);
        let field = |name: &str| form.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        let action = field("action").unwrap_or_default();
        s.log.push(
            format!("{} {} {action}", r.method, r.path)
                .trim_end()
                .to_owned(),
        );
        let mut answer = match (r.method, r.path) {
            ("GET", "/login/") => s.login_page(&sid),
            ("POST", "/login/") => {
                s.login_forms.push(form.clone());
                self.sign_in(&mut s, &sid, &field, &mut set)
            }
            ("GET", "/ports/") => s.ports_page(&sid, &self.username),
            ("POST", "/ports/") => s.port_call(&sid, r, &field),
            _ => Answer::new(404, "not found").html(),
        };
        for c in set {
            answer = answer.with("set-cookie", c);
        }
        answer
    }

    fn sign_in(
        &self,
        s: &mut State,
        sid: &str,
        field: &dyn Fn(&str) -> Option<String>,
        set: &mut Vec<String>,
    ) -> Answer {
        let csrf_ok = s
            .sessions
            .get(sid)
            .is_some_and(|x| field("csrfKey").as_deref() == Some(x.csrf.as_str()));
        if !csrf_ok {
            return Answer::new(
                403,
                "<html><body>The security key was invalid.</body></html>",
            )
            .html()
            .signed_in(false);
        }
        if s.knobs.after_login == AfterLogin::Locked {
            return s.login_page_with(
                sid,
                "You have been locked out for too many failed sign in attempts. Try again in 15 minutes.",
            );
        }
        let right = field("auth").as_deref() == Some(self.username.as_str())
            && field("password").as_deref() == Some(self.password.as_str())
            && field("_processLogin").as_deref() == Some("usernamepassword");
        if !right {
            return s.login_page_with(
                sid,
                "The password you entered is incorrect. Please try again (make sure your caps lock is off).",
            );
        }
        match s.knobs.after_login {
            AfterLogin::SecondFactor => {
                return Answer::new(
                    200,
                    "<html><head><title>Sign In - AirVPN</title></head><body><h1>Two-Factor Authentication</h1>\
                     <form method='post' action='https://airvpn.org/login/'><input type='hidden' name='csrfKey' value='x'>\
                     <input type='text' name='mfa_auth_code'><button type='submit'>Verify</button></form></body></html>",
                )
                .html()
                .signed_in(false);
            }
            AfterLogin::Unexpected => {
                return Answer::new(
                    200,
                    "<html><head><title>Maintenance - AirVPN</title></head><body><p>We will be back soon.</p></body></html>",
                )
                .html()
                .signed_in(false);
            }
            AfterLogin::Redirect | AfterLogin::Locked => {}
        }
        // Signed in: a new session id (as IPS does), the member's cookies, home.
        s.sessions.remove(sid);
        let id = s.new_session();
        if let Some(x) = s.sessions.get_mut(&id) {
            x.member = true;
        }
        s.sign_ins += 1;
        set.clear();
        set.push(format!("PHPSESSID={id}; path=/; secure; HttpOnly"));
        let logged = format!("{}", 1_793_613_700 + s.next);
        s.issued.push(logged.clone());
        set.push(format!("ips4_loggedIn={logged}; path=/; secure; HttpOnly"));
        set.push(
            "ips4_noCache=0; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/".to_owned(),
        );
        Answer::new(302, "")
            .with("location", "https://airvpn.org/")
            .signed_in(true)
    }
}

impl State {
    fn new_session(&mut self) -> String {
        self.next += 1;
        let n = self.next;
        let id = format!("sess{n:04}q8aq26b63fjhgo{n:02}");
        let csrf = format!("{:032x}", u128::from(n) * 0x9e37_79b9_7f4a_7c15);
        let token = format!(
            "{:032x}{:032x}",
            u128::from(n) * 0x0123_4567_89ab_cdef,
            u128::from(n + 7) * 0x0fed_cba9_8765_4321
        );
        self.issued
            .extend([id.clone(), csrf.clone(), token.clone()]);
        self.sessions.insert(
            id.clone(),
            Session {
                member: false,
                csrf,
                token,
                calls: 0,
            },
        );
        id
    }

    fn member(&self, sid: &str) -> bool {
        self.sessions.get(sid).is_some_and(|x| x.member)
    }

    fn login_page(&self, sid: &str) -> Answer {
        if self.member(sid) {
            return Answer::new(302, "")
                .with("location", "https://airvpn.org/")
                .signed_in(true);
        }
        let csrf = self.sessions.get(sid).map_or_default(|x| x.csrf.clone());
        let mut page = LOGIN_PAGE.replace(FIXTURE_CSRF, &csrf);
        match self.knobs.login_page {
            LoginPage::Normal => {}
            LoginPage::Captcha => {
                page = page.replace(
                    "<button type=\"submit\" name=\"_processLogin\"",
                    "<div class=\"g-recaptcha\" data-sitekey=\"6Lc-test\"></div><button type=\"submit\" name=\"_processLogin\"",
                );
            }
            LoginPage::NoCsrf => page = page.replace("name=\"csrfKey\"", "name=\"csrf_token\""),
        }
        Answer::new(200, page).html().signed_in(false)
    }

    fn login_page_with(&self, sid: &str, error: &str) -> Answer {
        let mut a = self.login_page(sid);
        let page = String::from_utf8(a.body).unwrap().replacen(
            "<ul class='ipsForm'>",
            &format!(
                "<div class=\"ipsMessage ipsMessage_error\">{error}</div>\n<ul class='ipsForm'>"
            ),
            1,
        );
        a.body = page.into_bytes();
        a
    }

    fn ports_page(&self, sid: &str, username: &str) -> Answer {
        let Some(x) = self.sessions.get(sid).filter(|x| x.member) else {
            return Answer::new(200, PORTS_SIGNED_OUT).html().signed_in(false);
        };
        let data = match self.knobs.ports_page {
            PortsPage::Normal => format!(
                "<div id='air_data' data-json=\"{{&quot;datetime_locale&quot;:&quot;browser&quot;,&quot;datetime_mode&quot;:&quot;auto&quot;,&quot;ecsrf&quot;:&quot;{}&quot;}}\"></div>",
                x.token
            ),
            PortsPage::NoAirData => String::new(),
        };
        Answer::new(
            200,
            format!(
                "<!DOCTYPE html><html><head><title>Forwarded ports - AirVPN</title></head><body>\
                 <a id='elUserLink'>{username} <i class='fa fa-caret-down'></i></a>\
                 <div class='air_page'>You are using {} of 5 ports.</div>{data}</body></html>",
                self.ports.len()
            ),
        )
        .html()
        .signed_in(true)
    }

    fn port_call(
        &mut self,
        sid: &str,
        r: &Request<'_>,
        field: &dyn Fn(&str) -> Option<String>,
    ) -> Answer {
        for (name, want) in [
            ("x-requested-with", "XMLHttpRequest"),
            ("origin", "https://airvpn.org"),
            ("referer", "https://airvpn.org/ports/"),
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            ),
        ] {
            if (r.header)(name).as_deref() != Some(want) {
                self.bad_xhr.push(name.into());
            }
        }
        if field("render").as_deref() != Some("ajax") {
            self.bad_xhr.push("render".into());
        }
        let fields = decode_form(r.body);
        self.calls
            .push(fields.into_iter().filter(|(n, _)| n != "ecsrf").collect());
        let signed_out = |style: SignedOut| match style {
            SignedOut::Page => Answer::new(200, PORTS_SIGNED_OUT).html().signed_in(false),
            SignedOut::Json => Answer::new(200, r#"{"error":"Login required."}"#).json(),
        };
        let expire = self.knobs.expire_after_calls;
        let style = self.knobs.signed_out;
        let Some(x) = self.sessions.get_mut(sid).filter(|x| x.member) else {
            return signed_out(style);
        };
        if self.knobs.refuse_every_call {
            return signed_out(style);
        }
        x.calls += 1;
        if expire.is_some_and(|n| x.calls > n) {
            // Once: the session ends, the next one lives on.
            self.knobs.expire_after_calls = None;
            self.sessions.remove(sid);
            return signed_out(style);
        }
        if field("ecsrf").as_deref() != Some(x.token.as_str()) {
            return Answer::new(200, r#"{"error":"Invalid ecsrf token"}"#).json();
        }
        match field("action").as_deref() {
            Some("manifest") => Answer::new(200, self.manifest()).json(),
            Some("insert") => self.insert(&field("port").unwrap_or_default()),
            Some("delete") => {
                let port: Option<u16> = field("port").and_then(|p| p.parse().ok());
                let pool: Option<u32> = field("pool").and_then(|p| p.parse().ok());
                let before = self.ports.len();
                self.ports
                    .retain(|p| Some(p.port) != port || Some(p.pool) != pool);
                if self.ports.len() == before {
                    Answer::new(200, r#"{"error":"Port not found."}"#).json()
                } else {
                    Answer::new(200, "[]").json()
                }
            }
            Some("pending") => Answer::new(200, "\"0\"").json(),
            Some(action) if action.starts_with("edit_") => self.edit(action, field),
            Some("sessions") => self.sessions(field),
            Some("test") => self.test(field),
            Some("ddns_report") => self.ddns_report(),
            Some("seq_search") => self.seq_search(field("n")),
            _ => Answer::new(200, r#"{"error":"Unknown action."}"#).json(),
        }
    }

    fn manifest(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(port_json).collect();
        format!(
            r#"{{"pool":2,"ports":[{}],"keys":[{{"id":"{DEVICE_ID}","name":"Default"}}]}}"#,
            ports.join(",")
        )
    }

    /// The reserved port a call names with `port` and `pool`.
    fn named(&mut self, field: &dyn Fn(&str) -> Option<String>) -> Option<usize> {
        let port: Option<u16> = field("port").and_then(|p| p.parse().ok());
        let pool: Option<u32> = field("pool").and_then(|p| p.parse().ok());
        let at = self
            .ports
            .iter()
            .position(|p| Some(p.port) == port && Some(p.pool) == pool);
        if at.is_none() {
            self.bad_xhr.push("port/pool".into());
        }
        at
    }

    /// `edit_*` with `port`, `pool`, `value`: one setting, checked as the page's server would.
    fn edit(&mut self, action: &str, field: &dyn Fn(&str) -> Option<String>) -> Answer {
        let Some(value) = field("value") else {
            self.bad_xhr.push(format!("{action}: value"));
            return Answer::error("Missing value.");
        };
        let Some(at) = self.named(field) else {
            return Answer::error("Port not found.");
        };
        match self.knobs.edit {
            Edit::Refuse(refused, message) if refused == action => return Answer::error(message),
            _ => {}
        }
        let valid = match action {
            "edit_note" => value.chars().count() <= 200,
            "edit_enabled" => value == "0" || value == "1",
            "edit_device" => value == "all" || value == DEVICE_ID,
            "edit_protocol" => ["both", "tcp", "udp"].contains(&value.as_str()),
            "edit_layer" => ["both", "v4", "v6"].contains(&value.as_str()),
            "edit_localport" => value.parse::<u16>().is_ok_and(|v| v > 0),
            "edit_ddns" => {
                value.len() <= 60
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }
            _ => return Answer::error("Unknown action."),
        };
        if !valid {
            self.bad_xhr.push(format!("{action}={value}"));
            return Answer::error("Invalid value.");
        }
        if !matches!(self.knobs.edit, Edit::Ignore(ignored) if ignored == action) {
            let p = &mut self.ports[at];
            match action {
                "edit_note" => p.notes = value,
                "edit_enabled" => p.enabled = value == "1",
                "edit_device" => p.device = value,
                "edit_protocol" => p.protocol = value,
                "edit_layer" => p.iplayer = value,
                "edit_localport" => p.local = value.parse().unwrap(),
                _ => p.dns = value,
            }
        }
        if self.knobs.edit == Edit::Garbled {
            return Answer::new(200, "<html><body>Saved</body></html>")
                .html()
                .signed_in(true);
        }
        Answer::new(200, r#"{"result":"saved"}"#).json()
    }

    /// `sessions` with `port`, `pool`: every connected session uses every enabled port.
    fn sessions(&mut self, field: &dyn Fn(&str) -> Option<String>) -> Answer {
        let Some(at) = self.named(field) else {
            return Answer::error("Port not found.");
        };
        let p = &self.ports[at];
        let items: Vec<String> = if p.enabled {
            self.knobs
                .sessions
                .iter()
                .map(|s| session_json(p, s))
                .collect()
        } else {
            Vec::new()
        };
        Answer::new(200, format!(r#"{{"items":[{}]}}"#, items.join(","))).json()
    }

    /// `test` with `ip`, `port`, `pool`, `protocol` of a TCP session item.
    fn test(&mut self, field: &dyn Fn(&str) -> Option<String>) -> Answer {
        let ip = field("ip").unwrap_or_default();
        if !self.knobs.sessions.iter().any(|s| s.server_ip == ip) {
            self.bad_xhr.push(format!("test ip {ip}"));
        }
        if field("protocol").as_deref() != Some("tcp") {
            self.bad_xhr.push("test protocol".into());
        }
        if self.named(field).is_none() {
            return Answer::error("Port not found.");
        }
        match self.knobs.probe {
            Probe::Verdict(word, message) => {
                Answer::new(200, format!(r#"{{"type":"{word}","message":"{message}"}}"#)).json()
            }
            Probe::Refuse(message) => Answer::error(message),
            Probe::Garbled => Answer::new(200, "<html><body>Error</body></html>")
                .html()
                .signed_in(true),
            Probe::Stall => Answer {
                stall: true,
                ..Answer::new(200, "")
            },
        }
    }

    /// `ddns_report`: each port's DDNS name, the sessions it leads to and their servers.
    fn ddns_report(&self) -> Answer {
        let server = |layer: &str| {
            self.knobs
                .sessions
                .iter()
                .find(|s| s.iplayer == layer)
                .map_or("", |s| s.server_ip)
        };
        let items: Vec<String> = self
            .ports
            .iter()
            .filter(|p| !p.dns.is_empty())
            .map(|p| {
                let sessions = i32::from(p.enabled && !self.knobs.sessions.is_empty());
                format!(
                    r#"{{"name":"{}","nsessions":{sessions},"ipv4":"{}","ipv6":"{}","ports":[{}]}}"#,
                    p.dns,
                    server("v4"),
                    server("v6"),
                    p.port
                )
            })
            .collect();
        Answer::new(
            200,
            format!(
                r#"{{"items":[{}],"services":{{"ns1.airdns.org":"ok"}}}}"#,
                items.join(",")
            ),
        )
        .json()
    }

    /// `seq_search` with `n`: the first `n` consecutive ports from 41000 nobody holds.
    fn seq_search(&mut self, n: Option<String>) -> Answer {
        let Some(n) = n
            .and_then(|n| n.parse::<u16>().ok())
            .filter(|n| (2..=10).contains(n))
        else {
            self.bad_xhr.push("seq_search n".into());
            return Answer::error("Invalid number of ports.");
        };
        let mut from = 41000u16;
        while (from..from + n).any(|p| self.ports.iter().any(|x| x.port == p)) {
            from += 1;
        }
        Answer::new(
            200,
            format!(
                r#"{{"message":"Ports <b>{from}-{}</b> are free right now."}}"#,
                from + n - 1
            ),
        )
        .json()
    }

    fn insert(&mut self, asked: &str) -> Answer {
        if let Insert::Refuse(message) = self.knobs.insert {
            return Answer::new(200, format!(r#"{{"error":"{message}"}}"#)).json();
        }
        if self.ports.len() >= 5 {
            return Answer::new(
                200,
                r#"{"error":"You have reached the maximum number of ports."}"#,
            )
            .json();
        }
        let port = if asked.is_empty() {
            let p = self.next_random;
            self.next_random += 1;
            p
        } else {
            match asked.parse::<u16>() {
                Ok(p) if p >= 2049 && !self.ports.iter().any(|x| x.port == p) => p,
                _ => return Answer::new(200, r#"{"error":"Port not available."}"#).json(),
            }
        };
        let new = FakePort::new(port);
        self.ports.push(new.clone());
        match self.knobs.insert {
            Insert::GarbledButDone => Answer::new(200, "<html><body>OK</body></html>")
                .html()
                .signed_in(true),
            _ => Answer::new(200, port_json(&new)).json(),
        }
    }
}

/// A port as the page's `manifest` and `insert` write it (a new one: `notes` null, `dns` "").
fn port_json(p: &FakePort) -> String {
    let notes = if p.notes.is_empty() {
        "null".to_owned()
    } else {
        format!("{:?}", p.notes)
    };
    format!(
        r#"{{"port":{},"pool":{},"notes":{notes},"enabled":{},"device":"{}","protocol":"{}","iplayer":"{}","local":{},"dns":"{}"}}"#,
        p.port, p.pool, p.enabled, p.device, p.protocol, p.iplayer, p.local, p.dns
    )
}

/// One item of `sessions`: the session `s` on port `p`.
fn session_json(p: &FakePort, s: &FakeSession) -> String {
    let client = if s.iplayer == "v6" {
        "fd7d:76ee:e68f:a993::2"
    } else {
        "10.128.0.2"
    };
    format!(
        r#"{{"port":{},"pool":{},"protocol":"{}","iplayer":"{}","dns_name":"{}","server_ip":"{}","server_country":"NL","server_name":"Alchiba","server_location":"Amsterdam","client_ip":"{client}","local":{},"notes":null,"device_name":"Default","device_description":""}}"#,
        p.port, p.pool, s.protocol, s.iplayer, p.dns, s.server_ip, p.local
    )
}

/// `application/x-www-form-urlencoded`, decoded.
pub fn decode_form(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (unescape(k), unescape(v))
        })
        .collect()
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
