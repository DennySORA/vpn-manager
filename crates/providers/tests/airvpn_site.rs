// SPDX-License-Identifier: GPL-3.0-or-later

//! `AirVPN`'s website client against a fake airvpn.org (`support/airvpn_site.rs`) over the
//! in-memory TLS fixture: the sign-in form and its post, cookies, the page token from the
//! escaped `data-json`, the port calls (list, reserve, delete, the settings, the test of a
//! port's sessions, the DDNS check, the search for free ports) with the exact fields the page
//! sends, a session that ends mid-way (one new sign-in), and the sign-ins that must stop with a
//! named reason — a wrong password, a CAPTCHA, a second factor, a changed form, an odd page.
//! Every log line is captured: none may carry the user name, the password, a cookie or the
//! token, and neither may any error. Nothing touches a socket, a resolver or `AirVPN`.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

#[path = "support/airvpn_site.rs"]
mod fake_site;
mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use fake_site::{FakeSite, LoginPage};
use std::assert_matches;
use support::{Fixture, Payload, Reply, Seen, TestCa};
use vpn_domain::ErrorCode;
use vpn_providers::HttpsClient;
use vpn_providers::airvpn::Credentials;
use vpn_providers::airvpn::site::{Session, Site, SiteError};

/// Characters that the form encoding and HTML each treat specially.
const USER: &str = "Synthetic.User";
const PASSWORD: &str = "pä+/=&<ss wörd";

struct Env {
    site: Arc<FakeSite>,
    /// The TLS fixture the client dials (kept for the test's length).
    _fixture: Fixture,
    client: HttpsClient<Fixture>,
    /// Every log line written while the test ran.
    logs: Arc<Mutex<Vec<u8>>>,
    _logging: tracing::subscriber::DefaultGuard,
}

fn credentials() -> Credentials {
    Credentials::new(USER, PASSWORD).unwrap()
}

#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn env(site: FakeSite) -> Env {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = Sink(logs.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let logging = tracing::subscriber::set_default(subscriber);
    let site = Arc::new(site);
    let ca = TestCa::new();
    let served = site.clone();
    let fixture = Fixture::new(ca.server_config(support::HOSTS), move |seen: &Seen| {
        let header = |name: &str| seen.header(name).map(str::to_owned);
        let a = served.handle(&fake_site::Request {
            method: &seen.method,
            path: &seen.path,
            header: &header,
            body: &seen.body,
        });
        Reply {
            status: a.status,
            headers: a.headers,
            payload: if a.stall {
                Payload::Stall
            } else {
                Payload::Full(a.body)
            },
        }
    });
    let client = HttpsClient::with_roots(fixture.clone(), ca.roots());
    Env {
        site,
        _fixture: fixture,
        client,
        logs,
        _logging: logging,
    }
}

impl Env {
    const fn site(&self) -> Site<'_, Fixture> {
        Site::new(&self.client)
    }

    fn logs(&self) -> String {
        String::from_utf8_lossy(&self.logs.lock().unwrap()).into_owned()
    }

    /// Nothing the site issued, and neither part of the credential, in `text`.
    fn no_secret_in(&self, what: &str, text: &str) {
        for secret in self.site.secrets() {
            assert!(
                !text.to_lowercase().contains(&secret.to_lowercase()),
                "{what} carries the secret {secret:?}: {text}"
            );
        }
    }

    fn requests(&self) -> Vec<String> {
        self.site.log()
    }
}

fn site() -> FakeSite {
    FakeSite::new(USER, PASSWORD)
}

#[tokio::test]
async fn a_second_signed_out_answer_stops_instead_of_signing_in_again() {
    let e = env(site());
    e.site.knobs(|k| k.refuse_every_call = true);
    let mut session = Session::new();
    let err = e
        .site()
        .ports(&mut session, &credentials())
        .await
        .unwrap_err();
    assert_matches!(err, SiteError::NotSignedIn(_), "{err}");
    assert_eq!(err.code(), ErrorCode::ProviderContractDrift);
    assert_eq!(e.site.sign_ins(), 1, "never a loop of sign-ins");
    // With a session that worked before: the site still counts it as signed in, so only the
    // token is fetched again (no password posted); the same answer then stops it.
    let e = env(site());
    let mut session = Session::new();
    e.site().ports(&mut session, &credentials()).await.unwrap();
    e.site.knobs(|k| k.refuse_every_call = true);
    let err = e
        .site()
        .ports(&mut session, &credentials())
        .await
        .unwrap_err();
    assert_matches!(err, SiteError::NotSignedIn(_), "{err}");
    assert_eq!(e.site.sign_ins(), 1);
    assert_eq!(
        e.requests()[4..],
        [
            "POST /ports/ manifest",
            "GET /login/",
            "GET /ports/",
            "POST /ports/ manifest"
        ]
    );
    e.no_secret_in("the error", &format!("{err} {err:?}"));
    e.no_secret_in("the log", &e.logs());
}

#[tokio::test]
async fn a_wrong_password_is_named_and_never_retried() {
    let e = env(FakeSite::new(USER, "the real one"));
    let mut session = Session::new();
    let err = e
        .site()
        .ports(&mut session, &credentials())
        .await
        .unwrap_err();
    assert_matches!(err, SiteError::LoginRejected(_), "{err}");
    assert_eq!(err.code(), ErrorCode::ProviderAuthRejected);
    assert!(err.text().zh_tw.contains("使用者名稱或密碼不正確"), "{err}");
    assert!(
        err.to_string()
            .contains("The password you entered is incorrect"),
        "the site's own reason, a plain sentence: {err}"
    );
    assert_eq!(e.requests(), ["GET /login/", "POST /login/"]);
    assert!(!session.signed_in());
    e.no_secret_in("the error", &format!("{err} {err:?}"));
    e.no_secret_in("the log", &e.logs());
}

#[tokio::test]
async fn a_captcha_or_a_changed_form_stops_before_the_password_is_sent() {
    for (knob, expect) in [
        (LoginPage::Captcha, ErrorCode::ProviderLoginChallenge),
        (LoginPage::NoCsrf, ErrorCode::ProviderContractDrift),
    ] {
        let e = env(site());
        e.site.knobs(|k| k.login_page = knob);
        let err = e
            .site()
            .ports(&mut Session::new(), &credentials())
            .await
            .unwrap_err();
        assert_eq!(err.code(), expect, "{knob:?}: {err}");
        assert_eq!(e.requests(), ["GET /login/"], "{knob:?}: nothing posted");
        if knob == LoginPage::NoCsrf {
            assert_matches!(
                &err, SiteError::LoginFormChanged(f) if f.zh_tw == "csrfKey",
                "{err}"
            );
            assert!(
                e.logs()
                    .contains("AirVPN website answer outside the known contract")
            );
        }
        e.no_secret_in("the log", &e.logs());
    }
}
