//! Per-request authorization by the connector: the client tells it which prepared request each
//! connection is for, confirms the request it is about to write right before the first byte, and
//! reports the answer. A refusal at either point sends nothing.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

mod support;

use std::io;
use std::sync::{Arc, Mutex};

use http::{HeaderMap, Method, StatusCode};
use std::assert_matches;
use support::{Fixture, HOSTS, Reply, TestCa};
use vpn_domain::ErrorCode;
use vpn_providers::https::Request;
use vpn_providers::{
    BoxedStream, Confirmation, Connect, Family, HttpError, HttpsClient, OpenError, Opened, Permit,
    ProviderError, Refusal, Target,
};

const HOST: &str = "api.mullvad.net";

/// What the authorizing connector saw.
#[derive(Default)]
struct Log {
    /// Digest of each prepared request, when its connection was asked for.
    prepared: Vec<[u8; 32]>,
    /// Digest of each request about to be written.
    confirmed: Vec<[u8; 32]>,
    answered: Vec<StatusCode>,
}

#[derive(Clone, Copy, PartialEq)]
enum Refuse {
    Never,
    AtConnect,
    AtFirstByte,
}

/// Wraps the fixture and issues a permit for every connection.
#[derive(Clone)]
struct Authorizing {
    inner: Fixture,
    log: Arc<Mutex<Log>>,
    refuse: Refuse,
}

struct Issued {
    log: Arc<Mutex<Log>>,
    refuse: bool,
}

impl Permit for Issued {
    fn confirm<'a>(&'a mut self, sent: &'a Target<'a>) -> Confirmation<'a> {
        self.log.lock().unwrap().confirmed.push(sent.digest());
        let refuse = self.refuse;
        Box::pin(async move {
            if refuse {
                Err(Refusal::new(
                    ErrorCode::ProviderPreflightFailed,
                    "出口在檢查後變更",
                ))
            } else {
                Ok(())
            }
        })
    }

    fn answered(&mut self, status: StatusCode, _: &HeaderMap) {
        self.log.lock().unwrap().answered.push(status);
    }
}

impl Connect for Authorizing {
    fn connect(
        &self,
        _: &str,
        _: u16,
        _: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send {
        std::future::ready(Err(io::Error::other("only connect_for")))
    }

    async fn connect_for<'a>(&'a self, target: &'a Target<'a>) -> Result<Opened<'a>, OpenError> {
        self.log.lock().unwrap().prepared.push(target.digest());
        if self.refuse == Refuse::AtConnect {
            return Err(OpenError::Refused(Refusal::new(
                ErrorCode::ProviderQuotaExceeded,
                "供應商請求額度暫時用完",
            )));
        }
        let mut opened = self.inner.connect_for(target).await?;
        opened.permit = Some(Box::new(Issued {
            log: self.log.clone(),
            refuse: self.refuse == Refuse::AtFirstByte,
        }));
        Ok(opened)
    }
}

fn client(refuse: Refuse, status: u16) -> (HttpsClient<Authorizing>, Fixture, Arc<Mutex<Log>>) {
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(HOSTS), move |_| Reply::json(status, "{}"));
    let log = Arc::new(Mutex::new(Log::default()));
    let connector = Authorizing {
        inner: fixture.clone(),
        log: log.clone(),
        refuse,
    };
    (HttpsClient::with_roots(connector, ca.roots()), fixture, log)
}

#[tokio::test]
async fn the_request_confirmed_is_the_one_prepared_and_its_answer_is_reported() {
    let (client, fixture, log) = client(Refuse::Never, 429);
    let r = client
        .send(Request::new(
            Method::DELETE,
            HOST,
            "/accounts/v1/devices/d1",
            Family::V4,
        ))
        .await
        .unwrap();
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let log = log.lock().unwrap();
    assert_eq!(log.prepared.len(), 1);
    assert_eq!(
        log.confirmed, log.prepared,
        "what is written is what was prepared"
    );
    assert_eq!(log.answered, vec![StatusCode::TOO_MANY_REQUESTS]);
    assert_eq!(fixture.seen().len(), 1);
    // Another method, path, host or family is another digest.
    let base = Target {
        method: &Method::DELETE,
        host: HOST,
        port: 443,
        path: "/accounts/v1/devices/d1",
        family: Family::V4,
        timeout: std::time::Duration::ZERO,
    };
    assert_eq!(base.digest(), log.prepared[0]);
    for other in [
        Target {
            method: &Method::GET,
            ..base
        },
        Target {
            path: "/accounts/v1/devices/d2",
            ..base
        },
        Target {
            host: "ipv4.am.i.mullvad.net",
            ..base
        },
        Target {
            family: Family::V6,
            ..base
        },
    ] {
        assert_ne!(other.digest(), base.digest(), "{other:?}");
    }
}

#[tokio::test]
async fn a_refusal_before_the_first_byte_sends_nothing() {
    let (client, fixture, log) = client(Refuse::AtFirstByte, 200);
    let e = client
        .send(Request::new(
            Method::GET,
            HOST,
            "/accounts/v1/devices",
            Family::V4,
        ))
        .await
        .unwrap_err();
    assert_matches!(&e, HttpError::Refused(r) if r.code == ErrorCode::ProviderPreflightFailed);
    assert!(!e.maybe_delivered());
    assert!(fixture.seen().is_empty(), "no request reached the server");
    assert_eq!(log.lock().unwrap().answered, Vec::<http::StatusCode>::new());
    // As a provider error it keeps its code and message.
    let p = ProviderError::from(e);
    assert_eq!(p.code(), ErrorCode::ProviderPreflightFailed);
    assert_eq!(p.to_string(), "出口在檢查後變更");
    assert!(!p.outcome_unknown());
}

#[tokio::test]
async fn a_refusal_at_connect_dials_nothing() {
    let (client, fixture, _) = client(Refuse::AtConnect, 200);
    let e = client
        .send(Request::new(Method::GET, HOST, "/", Family::V4))
        .await
        .unwrap_err();
    assert_matches!(&e, HttpError::Refused(r) if r.code == ErrorCode::ProviderQuotaExceeded);
    assert_eq!(fixture.dials(), []);
}

#[tokio::test]
async fn an_airvpn_bootstrap_refusal_ends_the_request_instead_of_trying_the_next_address() {
    let (client, fixture, log) = client(Refuse::AtConnect, 200);
    let credentials = vpn_providers::airvpn::Credentials::new("user", "secret").unwrap();
    let e = vpn_providers::airvpn::AirVpn::new(client.connector().clone())
        .user(&credentials)
        .await
        .unwrap_err();
    assert_matches!(e, ProviderError::Refused(_));
    assert_eq!(
        log.lock().unwrap().prepared.len(),
        1,
        "one attempt, not four"
    );
    assert_eq!(fixture.dials(), []);
}
