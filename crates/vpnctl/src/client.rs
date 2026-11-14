//! HTTP/1.1 to the controller over `api.sock`: one connection per request, bounded answers,
//! and changes sent once with an Idempotency-Key. A change whose answer was lost is followed up
//! through the operation recorded under its key — never sent again (it may have run).

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use tokio::time::Instant;
use vpn_domain::{ApiError, ErrorCode, Operation, OperationStatus};

use crate::cmd::Failure;

/// Largest answer read (the biggest is the diagnostics report).
const RESPONSE_MAX: usize = 16 * 1024 * 1024;
/// Longer than the controller's own 30 s call timeout: it answers first, with a reason.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
/// How long a lost answer is looked up before the outcome is reported unknown.
const FOLLOW_FOR: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(500);

pub struct Client {
    socket: PathBuf,
}

/// An answer of the controller.
pub struct Answer {
    pub status: StatusCode,
    pub body: Bytes,
    /// Strong `ETag` (`"<revision>"`), when the resource has one.
    pub etag: Option<u64>,
}

/// Why a request got no answer.
pub enum Transport {
    /// It never reached the controller (no socket, connection refused): nothing happened.
    NotSent(String),
    /// It may have reached the controller.
    Lost(String),
}

/// The result of a change.
pub enum Mutation<T> {
    /// The answer (`None` for 204 No Content).
    Done(Option<T>),
    /// The answer was lost; the operation recorded under the request's key says it succeeded.
    Recovered(Box<Operation>),
}

fn connect_error(socket: &Path, e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "找不到 {}：VPN Manager 的 controller 沒有在執行，或 --state-dir 指向別的安裝",
            socket.display()
        ),
        std::io::ErrorKind::ConnectionRefused => {
            format!("{} 沒有程式在接聽：controller 可能已停止", socket.display())
        }
        std::io::ErrorKind::PermissionDenied => {
            format!("沒有權限連線到 {}（只接受同一個使用者）", socket.display())
        }
        _ => format!("無法連線到 {}：{e}", socket.display()),
    }
}

/// The error an answer carries (a synthesized one when the body is not an `ApiError`).
pub fn api_error(a: &Answer) -> ApiError {
    serde_json::from_slice::<ApiError>(&a.body).unwrap_or_else(|_| {
        ApiError::new(
            ErrorCode::Internal,
            format!("controller 回應 HTTP {}", a.status.as_u16()),
        )
    })
}

pub fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(body).map_err(|e| Failure::Invalid(format!("無法解讀回應：{e}")))
}

impl Client {
    pub const fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// One request on a new connection.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        headers: &[(&'static str, String)],
    ) -> Result<Answer, Transport> {
        vpn_platform::paths::verify_socket_dir(&self.socket).map_err(|e| {
            Transport::NotSent(format!("不連線：API socket 所在的目錄不可信任（{e}）"))
        })?;
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| Transport::NotSent(connect_error(&self.socket, &e)))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| Transport::NotSent(e.to_string()))?;
        tokio::spawn(async move {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "a connection failure that matters fails the request (send_request or the body read); after the answer it changes nothing"
            )]
            let _ = conn.await;
        });
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("accept", "application/json");
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let req = req
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Transport::NotSent(e.to_string()))?;
        // From here on the controller may have received it.
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_elapsed| Transport::Lost("沒有在時限內收到回應".into()))?
            .map_err(|e| Transport::Lost(e.to_string()))?;
        let status = resp.status();
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim_start_matches("W/").trim_matches('"').parse().ok());
        let body = Limited::new(resp.into_body(), RESPONSE_MAX)
            .collect()
            .await
            .map_err(|e| Transport::Lost(e.to_string()))?
            .to_bytes();
        Ok(Answer { status, body, etag })
    }

    /// Read a JSON resource.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Failure> {
        Ok(self.get_tagged(path).await?.0)
    }

    /// Read a JSON resource and its `ETag` revision.
    pub async fn get_tagged<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<(T, Option<u64>), Failure> {
        match self.send(Method::GET, path, None, &[]).await {
            Ok(a) if a.status.is_success() => Ok((parse(&a.body)?, a.etag)),
            Ok(a) => Err(Failure::Api(api_error(&a))),
            Err(Transport::NotSent(m) | Transport::Lost(m)) => Err(Failure::Unreachable(m)),
        }
    }

    /// A POST that changes nothing (a test): no Idempotency-Key, and a lost answer is only that —
    /// nothing to follow up.
    pub async fn post<T: DeserializeOwned>(&self, path: &str) -> Result<T, Failure> {
        match self
            .send(Method::POST, path, Some(b"{}".to_vec()), &[])
            .await
        {
            Ok(a) if a.status.is_success() => parse(&a.body),
            Ok(a) => Err(Failure::Api(api_error(&a))),
            Err(Transport::NotSent(m) | Transport::Lost(m)) => Err(Failure::Unreachable(m)),
        }
    }

    /// Send a change once, with a fresh Idempotency-Key (and `If-Match` when given). When the
    /// answer is lost or says the outcome is unknown, the operation recorded under the key is
    /// looked up instead of sending the change again.
    pub async fn mutate<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + Sync)>,
        if_match: Option<u64>,
    ) -> Result<Mutation<T>, Failure> {
        let key = uuid::Uuid::new_v4().to_string();
        let mut headers = vec![("idempotency-key", key.clone())];
        if let Some(r) = if_match {
            headers.push(("if-match", format!("\"{r}\"")));
        }
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| Failure::Invalid(e.to_string()))?;
        match self.send(method, path, bytes, &headers).await {
            Ok(a) if a.status == StatusCode::NO_CONTENT => Ok(Mutation::Done(None)),
            Ok(a) if a.status.is_success() => Ok(Mutation::Done(Some(parse(&a.body)?))),
            Ok(a) => {
                let e = api_error(&a);
                if matches!(e.code, ErrorCode::OutcomeUnknown | ErrorCode::Timeout) {
                    self.follow_key(&key, e.message.zh_tw.as_str()).await
                } else {
                    Err(Failure::Api(e))
                }
            }
            Err(Transport::NotSent(m)) => Err(Failure::Unreachable(m)),
            Err(Transport::Lost(m)) => self.follow_key(&key, &m).await,
        }
    }

    /// What happened to the change sent under `key`: waits while it runs or while the
    /// controller or manager is unreachable, at most [`FOLLOW_FOR`].
    async fn follow_key<T>(&self, key: &str, cause: &str) -> Result<Mutation<T>, Failure> {
        let deadline = Instant::now() + FOLLOW_FOR;
        let path = format!("/v1/operations/by-key/{key}");
        let mut last: Option<Box<Operation>> = None;
        loop {
            match self.send(Method::GET, &path, None, &[]).await {
                Ok(a) if a.status.is_success() => {
                    let op: Box<Operation> = Box::new(parse(&a.body)?);
                    match op.status {
                        OperationStatus::Succeeded => return Ok(Mutation::Recovered(op)),
                        OperationStatus::Failed => {
                            return Err(Failure::Api(op.error.clone().unwrap_or_else(|| {
                                ApiError::new(ErrorCode::Internal, "操作失敗")
                            })));
                        }
                        OperationStatus::Unknown | OperationStatus::Cancelled => {
                            return Err(Failure::Unknown {
                                key: Some(key.to_string()),
                                why: format!("操作的結果未知（{cause}）"),
                                operation: Some(op),
                            });
                        }
                        OperationStatus::Accepted | OperationStatus::Running => last = Some(op),
                    }
                }
                Ok(a) if a.status == StatusCode::NOT_FOUND => {
                    return Err(Failure::Unknown {
                        key: Some(key.to_string()),
                        why: format!(
                            "沒有收到回應（{cause}），也查不到這個請求的紀錄：它可能沒有送達，也可能還沒被記錄；不要假設它已經或沒有執行"
                        ),
                        operation: None,
                    });
                }
                // The controller or the manager is not reachable right now: keep looking.
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(Failure::Unknown {
                    key: Some(key.to_string()),
                    why: format!(
                        "沒有收到回應（{cause}），{} 秒內也沒有查到結果",
                        FOLLOW_FOR.as_secs()
                    ),
                    operation: last,
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }
}
