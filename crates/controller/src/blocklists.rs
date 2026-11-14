//! IP blocklists in the controller: preview, download, commit and refresh.
//!
//! The controller previews text, downloads URL sources through the Provider egress connection
//! (never the host network: the controller cannot dial), commits content to the manager, and
//! refreshes URL sources on request or when an automatic refresh is due.
//!
//! A failed refresh keeps the last good content and marks the list stale with the reason; empty
//! or mostly invalid content (an error page) is a failure, never published as success.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use vpn_domain::blocklist::{
    BlocklistError, HttpsUrl, MAX_RAW_BYTES, ParsedBlocklist, SAMPLE_RANGES, parse, parse_https_url,
};
use vpn_domain::validation::check_blocklist;
use vpn_domain::{
    ApiError, Blocklist, BlocklistFetch, BlocklistId, BlocklistInput, BlocklistPreview,
    BlocklistSource, BlocklistStats, BlocklistUpdate, BlocklistView, BuiltinBlocklistState,
    EgressMode, EntityMeta, ErrorCode, FieldError, RouteMode, Severity, Text, Timestamp, tr,
};
use vpn_ipc::control::{Call, Reply};
use vpn_providers::fetch::{DownloadError, download as fetch};
use vpn_providers::{Connect, Family, HttpError, HttpsClient, Refusal};
use vpn_sync::Mutex;

use crate::link::ManagerLink;
use crate::provider::Route;

/// One download (both address families together) ends within this: below the 30 s a browser
/// waits for a change before reporting an unknown outcome.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(25);
/// How often due automatic refreshes are looked for.
const SCHEDULE_TICK: Duration = Duration::from_secs(60);

/// One change at a time per list (a manual refresh, the schedule, an edit).
static LOCKS: LazyLock<Mutex<HashMap<BlocklistId, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Mutex::default);

fn lock_for(id: BlocklistId) -> Arc<tokio::sync::Mutex<()>> {
    LOCKS.lock().entry(id).or_default().clone()
}

fn field(path: &str, code: &str, message: impl Into<Text>) -> ApiError {
    let message = message.into();
    ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![FieldError {
        path: path.into(),
        code: code.into(),
        message,
    }])
}

/// A text that cannot be used at all, as an API error.
#[must_use]
pub fn parse_error(e: &BlocklistError) -> ApiError {
    let code = match e {
        BlocklistError::TooLarge => ErrorCode::PayloadTooLarge,
        BlocklistError::Compressed(_) => ErrorCode::UnsupportedMediaType,
        BlocklistError::TooManyEntries | BlocklistError::TooLargeParsed => {
            ErrorCode::ValidationFailed
        }
    };
    ApiError::new(code, e.text())
}

fn fetch_failed(why: impl Into<Text>) -> ApiError {
    ApiError::new(
        ErrorCode::BlocklistFetchFailed,
        tr!(
            "Download failed: {why}",
            "下載失敗：{why}",
            "ダウンロードに失敗しました：{why}";
            why = why
        ),
    )
}

/// A downloaded URL source, parsed.
#[derive(Debug)]
pub struct Downloaded {
    pub parsed: ParsedBlocklist,
    pub fetch: BlocklistFetch,
}

/// Why a list cannot be downloaded over a route that is not a VPN egress connection.
fn only_via_vpn() -> Text {
    tr!(
        "IP blocklists are downloaded only through a VPN connection; the first direct connection is only for provider accounts. Choose a Provider egress connection first",
        "IP 封鎖清單只經 VPN 連線下載；首次直連只用於供應商帳號。請先選擇 Provider 出口連線",
        "IP ブロックリストは VPN 接続経由でのみダウンロードします。初回の直接接続はプロバイダーのアカウント専用です。先に Provider 出口接続を選んでください"
    )
}

/// Download `url` through the selected Provider egress connection and parse it.
///
/// # Errors
///
/// A validation error for a URL that is not `https://`, a Provider egress error when there
/// is no usable route, and otherwise as for [`download_via`].
pub async fn download(link: &ManagerLink, url: &str) -> Result<Downloaded, ApiError> {
    let url: HttpsUrl =
        parse_https_url(url).map_err(|m| field("/source/url", "BLOCKLIST_URL", m))?;
    let route = crate::provider::route(link).await?;
    let client = HttpsClient::new(route.relay.clone());
    download_via(&route, &client, &url).await
}

/// Download `url` over `route` with `client` (built on the route's relay) and parse it. Only a
/// VPN egress route carries a list: the first-setup direct exception is refused before anything
/// is sent.
///
/// # Errors
///
/// `PROVIDER_EGRESS_BLOCKED` when `route` is not a VPN egress connection,
/// `PAYLOAD_TOO_LARGE` for content over [`MAX_RAW_BYTES`], `BLOCKLIST_FETCH_FAILED` when
/// the download fails, and the parse error of content that cannot be used ([`parse_error`]).
pub async fn download_via<C: Connect>(
    route: &Route,
    client: &HttpsClient<C>,
    url: &HttpsUrl,
) -> Result<Downloaded, ApiError> {
    let (Some(instance_id), Some(generation), RouteMode::ViaInstance) =
        (route.instance_id, route.generation, route.mode)
    else {
        return Err(ApiError::new(
            ErrorCode::ProviderEgressBlocked,
            only_via_vpn(),
        ));
    };
    let deadline = tokio::time::Instant::now() + DOWNLOAD_TIMEOUT;
    // What went wrong with each family tried. When IPv4 could not connect and IPv6 failed too,
    // both are reported: the IPv4 reason (say, a refused connection) is often the one that
    // matters, not the IPv6 one (say, a destination the policy does not allow).
    let mut failures: Vec<(Family, DownloadError)> = Vec::new();
    // IPv4 first; IPv6 only when IPv4 could not even connect (no such address, no route).
    for family in [Family::V4, Family::V6] {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match fetch(client, url, family, MAX_RAW_BYTES, left).await {
            Ok(d) => {
                let bytes = u32::try_from(d.body.len()).unwrap_or(u32::MAX);
                let parsed = parse(&d.body).map_err(|e| parse_error(&e))?;
                return Ok(Downloaded {
                    parsed,
                    fetch: BlocklistFetch {
                        url: d.url.to_url(),
                        bytes,
                        content_type: d.content_type,
                        via_instance_id: instance_id,
                        via_generation: generation,
                    },
                });
            }
            Err(DownloadError::Http(HttpError::TooLarge { .. })) => {
                let mib = MAX_RAW_BYTES / 1024 / 1024;
                return Err(ApiError::new(
                    ErrorCode::PayloadTooLarge,
                    tr!(
                        "The list is over the {mib} MiB limit",
                        "清單超過 {mib} MiB 上限",
                        "リストが上限の {mib} MiB を超えています"
                    ),
                ));
            }
            Err(e) => {
                let connect = matches!(e, DownloadError::Http(HttpError::Connect(_)));
                failures.push((family, e));
                if !connect {
                    break;
                }
            }
        }
    }
    Err(fetch_failed(download_failure(&failures)))
}

/// The reason of a failed download: one family's error as is, several labelled by family.
fn download_failure(failures: &[(Family, DownloadError)]) -> Text {
    // A connection failure already says what failed ("經 tunnel 連線失敗：…"): the connector's
    // refusal carried in the I/O error, or the operating system's own words.
    let reason = |e: &DownloadError| match e {
        DownloadError::Http(HttpError::Connect(io)) => io
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Refusal>())
            .map_or_else(|| Text::verbatim(io.to_string()), |r| r.message.clone()),
        other => other.text(),
    };
    match failures {
        [] => tr!("cannot connect", "無法連線", "接続できません"),
        [(_, e)] => reason(e),
        all => {
            let mut parts = all.iter().map(|(family, e)| {
                let label = match family {
                    Family::V4 => "IPv4",
                    Family::V6 => "IPv6",
                };
                tr!(
                    "{label} {why}",
                    "{label} {why}",
                    "{label} {why}";
                    why = reason(e)
                )
            });
            let first = parts.next().unwrap_or_default();
            parts.fold(first, |done, part| {
                tr!(
                    "{done}; {part}",
                    "{done}；{part}",
                    "{done}；{part}";
                    done = done,
                    part = part
                )
            })
        }
    }
}

/// What a preview shows. `url_source`: content of a URL source, which must not look like an error
/// page either.
#[must_use]
pub fn preview(
    parsed: &ParsedBlocklist,
    fetched: Option<BlocklistFetch>,
    url_source: bool,
) -> BlocklistPreview {
    BlocklistPreview {
        import_hash: parsed.import_hash(),
        stats: parsed.stats.clone(),
        sample: parsed.set.labels(SAMPLE_RANGES),
        invalid_lines: parsed.invalid.clone(),
        problems: problems(parsed, url_source),
        fetched,
    }
}

fn problems(parsed: &ParsedBlocklist, url_source: bool) -> Vec<Text> {
    // Nothing valid, or only private and special-use space (left out of every list).
    if let Some(why) = parsed.unusable() {
        return vec![why];
    }
    if url_source && let Some(a) = parsed.anomaly() {
        return vec![a];
    }
    Vec::new()
}

/// Refuse content that cannot be saved, and content other than what the user previewed.
fn accept(parsed: &ParsedBlocklist, url_source: bool, expected: &str) -> Result<(), ApiError> {
    if let Some(problem) = problems(parsed, url_source).into_iter().next() {
        return Err(field("/text", "BLOCKLIST_UNUSABLE", problem));
    }
    if parsed.import_hash() != expected {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            tr!(
                "The list content differs from the preview (it may have been updated); preview it again before saving",
                "清單內容與預覽時不同（可能已經更新），請重新預覽後再儲存",
                "リストの内容がプレビュー時と異なります（更新された可能性があります）。もう一度プレビューしてから保存してください"
            ),
        ));
    }
    Ok(())
}

fn validate(name: &str, source: &BlocklistSource) -> Result<BlocklistSource, ApiError> {
    let report = check_blocklist(name, source);
    if report.has_errors() {
        let fields: Vec<FieldError> = report
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .map(|i| FieldError {
                path: i.path.clone(),
                code: i.code.clone(),
                message: i.message.clone(),
            })
            .collect();
        let message = fields.first().map_or_default(|f| f.message.clone());
        return Err(ApiError::new(ErrorCode::ValidationFailed, message).with_fields(fields));
    }
    // Stored in its canonical form.
    Ok(match source {
        BlocklistSource::Url { url, refresh_hours } => BlocklistSource::Url {
            url: parse_https_url(url).map_or_else(|_| url.clone(), |u| u.to_url()),
            refresh_hours: *refresh_hours,
        },
        BlocklistSource::Upload => BlocklistSource::Upload,
    })
}

fn with_content(mut list: Blocklist, parsed: &ParsedBlocklist) -> Blocklist {
    list.stats = parsed.stats.clone();
    list.content_sha256 = parsed.import_hash();
    list.content_updated_at = Timestamp::now();
    list.invalid_lines.clone_from(&parsed.invalid);
    list
}

async fn put(
    link: &ManagerLink,
    list: Blocklist,
    expected_revision: Option<u64>,
    parsed: Option<ParsedBlocklist>,
) -> Result<BlocklistView, ApiError> {
    match link
        .call(Call::PutBlocklist {
            list: Box::new(list),
            expected_revision,
            set: parsed.map(|p| p.set),
        })
        .await?
    {
        Reply::Blocklist(v) => Ok(*v),
        _ => Err(ApiError::internal()),
    }
}

/// A list as the manager has it (no `waiting`: see [`view`]).
async fn stored(link: &ManagerLink, id: BlocklistId) -> Result<BlocklistView, ApiError> {
    match link.call(Call::Blocklist(id)).await? {
        Reply::Blocklist(v) => Ok(*v),
        _ => Err(ApiError::internal()),
    }
}

/// One list, with why it cannot be downloaded now (`waiting`).
///
/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn view(link: &ManagerLink, id: BlocklistId) -> Result<BlocklistView, ApiError> {
    Ok(annotated(link, stored(link, id).await?).await)
}

/// Every list, with why the URL lists cannot be downloaded now (`waiting`).
///
/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn views(link: &ManagerLink) -> Result<Vec<BlocklistView>, ApiError> {
    Ok(views_waiting(link).await?.0)
}

/// Every list with `waiting` filled in, and why the URL lists among them cannot be downloaded
/// now (`None` when they can, or there is none).
async fn views_waiting(link: &ManagerLink) -> Result<(Vec<BlocklistView>, Option<Text>), ApiError> {
    let Reply::Blocklists(mut all) = link.call(Call::Blocklists).await? else {
        return Err(ApiError::internal());
    };
    let mut reason = None;
    if all.iter().any(downloads) {
        reason = egress_unavailable(link).await;
        for v in all.iter_mut().filter(|v| downloads(v)) {
            v.waiting.clone_from(&reason);
        }
    }
    Ok((all, reason))
}

/// `v` with `waiting` filled in.
pub async fn annotated(link: &ManagerLink, mut v: BlocklistView) -> BlocklistView {
    if downloads(&v) {
        v.waiting = egress_unavailable(link).await;
    }
    v
}

/// `BlocklistView::waiting`, which is plain text: the Traditional Chinese words until it carries
/// the three languages.
/// An enabled URL list: one the controller downloads (on request or on schedule).
const fn downloads(v: &BlocklistView) -> bool {
    v.blocklist.enabled && matches!(v.blocklist.source, BlocklistSource::Url { .. })
}

/// Why URL lists cannot be downloaded right now.
///
/// `None` when the Provider egress is a VPN connection that can carry them. Lists wait for it: nothing else (and never the host network
/// or the first-setup direct exception) carries them.
pub async fn egress_unavailable(link: &ManagerLink) -> Option<Text> {
    // The same conditions as `download`'s route, said for a list rather than a provider call.
    let (egress, _) = match crate::provider::egress(link).await {
        Ok(binding) => binding,
        Err(e) => {
            return Some(tr!(
                "Cannot read the Provider egress: {why}",
                "無法讀取 Provider 出口：{why}",
                "Provider 出口を読み取れません：{why}";
                why = e.message
            ));
        }
    };
    if egress.desired_mode == EgressMode::Disabled {
        return Some(tr!(
            "The Provider egress is disabled; lists are downloaded once an egress connection is chosen",
            "Provider 出口已停用；選擇出口連線後才會下載",
            "Provider 出口は無効です。出口接続を選ぶとダウンロードします"
        ));
    }
    let Some(id) = egress.selected_instance_id else {
        // The interface adds that lists are downloaded only through a VPN connection.
        return Some(tr!(
            "No Provider egress connection is chosen yet",
            "還沒有選擇 Provider 出口連線",
            "Provider 出口接続がまだ選ばれていません"
        ));
    };
    match link.call(Call::ProviderRoute(id)).await {
        Ok(Reply::ProviderRoute { .. }) => None,
        _ => Some(tr!(
            "The Provider egress connection is not ready yet (not connected, starting or stopped); lists are downloaded automatically once it is ready",
            "Provider 出口連線還沒有就緒（尚未連線、啟動中或已停止）；就緒後自動下載",
            "Provider 出口接続はまだ準備完了ではありません（未接続、起動中、または停止中）。準備完了になると自動でダウンロードします"
        )),
    }
}

/// What a download that stored content says: `entries` entries, downloaded for the first time
/// (`first`) or updated.
fn content_message(entries: u32, first: bool) -> Text {
    match (first, entries) {
        (true, 1) => tr!(
            "Downloaded 1 entry",
            "已下載 1 筆",
            "1 件をダウンロードしました"
        ),
        (true, _) => tr!(
            "Downloaded {entries} entries",
            "已下載 {entries} 筆",
            "{entries} 件をダウンロードしました"
        ),
        (false, 1) => tr!("Updated to 1 entry", "已更新為 1 筆", "1 件に更新しました"),
        (false, _) => tr!(
            "Updated to {entries} entries",
            "已更新為 {entries} 筆",
            "{entries} 件に更新しました"
        ),
    }
}

async fn record(
    link: &ManagerLink,
    id: BlocklistId,
    ok: bool,
    message: Text,
) -> Result<BlocklistView, ApiError> {
    match link
        .call(Call::BlocklistRefreshed {
            id,
            ok,
            message: Some(message),
        })
        .await?
    {
        Reply::Blocklist(v) => Ok(*v),
        _ => Err(ApiError::internal()),
    }
}

/// Record a refresh that failed with `e`, best effort: the caller returns `e` either way. When
/// the record fails too, the list keeps showing its previous refresh, and that is logged.
async fn record_failure(link: &ManagerLink, id: BlocklistId, e: &ApiError) {
    if let Err(not_recorded) = record(link, id, false, e.message.clone()).await {
        tracing::warn!(blocklist = %id, error = %not_recorded, "failed blocklist refresh not recorded");
    }
}

/// `POST /v1/blocklists`: the server parses (or downloads) the content again and stores it only
/// if it is what the preview showed.
///
/// # Errors
///
/// A validation error for the name or source, a download or parse error for the content, a
/// conflict when it is not what the preview showed, and the manager's error when storing fails.
pub async fn create(link: &ManagerLink, input: BlocklistInput) -> Result<BlocklistView, ApiError> {
    let source = validate(&input.name, &input.source)?;
    let (parsed, url) = match &source {
        BlocklistSource::Upload => {
            let text = input.text.as_deref().ok_or_else(|| {
                field(
                    "/text",
                    "BLOCKLIST_TEXT",
                    tr!(
                        "Provide the list content",
                        "請提供清單內容",
                        "リストの内容を入力してください"
                    ),
                )
            })?;
            (parse(text.as_bytes()).map_err(|e| parse_error(&e))?, false)
        }
        BlocklistSource::Url { url, .. } => {
            if input.text.is_some() {
                return Err(field("/text", "BLOCKLIST_TEXT", no_text_for_url()));
            }
            (download(link, url).await?.parsed, true)
        }
    };
    accept(&parsed, url, &input.expected_import_hash)?;
    let now = Timestamp::now();
    let list = with_content(
        Blocklist {
            id: BlocklistId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: now,
                updated_at: now,
            },
            name: input.name.trim().to_string(),
            source,
            stats: BlocklistStats::default(),
            content_sha256: String::new(),
            content_updated_at: now,
            invalid_lines: Vec::new(),
            builtin: None,
            enabled: true,
        },
        &parsed,
    );
    let id = list.id;
    let entries = parsed.stats.entries;
    let created = put(link, list, None, Some(parsed)).await?;
    // The first download is the first successful refresh.
    if url && let Ok(v) = record(link, id, true, content_message(entries, true)).await {
        return Ok(v);
    }
    Ok(created)
}

/// A URL source's content comes from the server's download, never from the request.
fn no_text_for_url() -> Text {
    tr!(
        "The content of a URL source is downloaded by the server; text content is not accepted",
        "網址來源的內容由伺服器下載，不接受文字內容",
        "URL ソースの内容はサーバーがダウンロードするため、テキストの内容は受け付けません"
    )
}

/// `PUT /v1/blocklists/{id}`.
///
/// # Errors
///
/// A validation error for the change, a download or parse error for new content, and the
/// manager's error (a revision conflict, an unknown list) when storing fails.
pub async fn update(
    link: &ManagerLink,
    id: BlocklistId,
    revision: u64,
    input: BlocklistUpdate,
) -> Result<BlocklistView, ApiError> {
    let lock = lock_for(id);
    let _one = lock.lock().await;
    let current = stored(link, id).await?.blocklist;
    let source = validate(&input.name, &input.source)?;
    // A built-in list stays what the catalogue names: only its interval (and name) change.
    if let Some(b) = current
        .builtin
        .as_deref()
        .and_then(vpn_domain::builtin_blocklists::builtin)
        && !matches!(&source, BlocklistSource::Url { url, .. } if url == b.url)
    {
        return Err(field(
            "/source/url",
            "BLOCKLIST_BUILTIN",
            tr!(
                "The source of a built-in list cannot be changed; for another source, add a list",
                "內建清單的來源不能更改；需要其他來源請新增一份清單",
                "組み込みリストのソースは変更できません。別のソースが必要なら、新しいリストを追加してください"
            ),
        ));
    }
    let content = match (&source, input.text.as_deref(), &input.expected_import_hash) {
        (BlocklistSource::Upload, Some(text), Some(expected)) => {
            let parsed = parse(text.as_bytes()).map_err(|e| parse_error(&e))?;
            accept(&parsed, false, expected)?;
            Some(parsed)
        }
        (BlocklistSource::Upload, Some(_), None) => {
            return Err(field(
                "/expected_import_hash",
                "BLOCKLIST_HASH",
                tr!(
                    "New content must be previewed first",
                    "新的內容需要先預覽",
                    "新しい内容は先にプレビューしてください"
                ),
            ));
        }
        (BlocklistSource::Upload, None, _) => None,
        (BlocklistSource::Url { .. }, Some(_), _) => {
            return Err(field("/text", "BLOCKLIST_TEXT", no_text_for_url()));
        }
        (BlocklistSource::Url { url, .. }, None, Some(expected)) => {
            let parsed = download(link, url).await?.parsed;
            accept(&parsed, true, expected)?;
            Some(parsed)
        }
        (BlocklistSource::Url { url, .. }, None, None) => {
            let same =
                matches!(&current.source, BlocklistSource::Url { url: was, .. } if was == url);
            if !same {
                return Err(field(
                    "/source/url",
                    "BLOCKLIST_HASH",
                    tr!(
                        "Before changing the URL, preview the content of the new one",
                        "更換網址前請先預覽新網址的內容",
                        "URL を変更する前に、新しい URL の内容をプレビューしてください"
                    ),
                ));
            }
            None
        }
    };
    let downloaded = content.is_some() && matches!(source, BlocklistSource::Url { .. });
    let entries = content.as_ref().map(|p| p.stats.entries);
    let mut list = Blocklist {
        name: input.name.trim().to_string(),
        source,
        enabled: input.enabled.unwrap_or(current.enabled),
        ..current
    };
    if let Some(parsed) = &content {
        list = with_content(list, parsed);
    }
    let saved = put(link, list, Some(revision), content).await?;
    if downloaded
        && let Some(n) = entries
        && let Ok(v) = record(link, id, true, content_message(n, true)).await
    {
        return Ok(v);
    }
    Ok(saved)
}

/// Refresh a URL source now.
///
/// A failure is recorded (the list turns stale, the last good content stays) and returned — except when there is no usable Provider egress: that is not the list's
/// failure, the list waits for one (`waiting`) and is downloaded as soon as there is.
///
/// # Errors
///
/// A validation error for a list that is not a URL source, the recorded download or parse
/// failure, and the manager's error.
pub async fn refresh(link: &ManagerLink, id: BlocklistId) -> Result<BlocklistView, ApiError> {
    let lock = lock_for(id);
    let _one = lock.lock().await;
    let current = stored(link, id).await?.blocklist;
    let BlocklistSource::Url { url, .. } = &current.source else {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            tr!(
                "Only a list with a URL source can be downloaded again",
                "只有網址來源的清單可以重新下載",
                "再ダウンロードできるのは URL ソースのリストだけです"
            ),
        ));
    };
    if !current.enabled {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            tr!(
                "This list is disabled; it is downloaded once it is enabled",
                "這份清單已停用；啟用後才會下載",
                "このリストは無効です。有効にするとダウンロードされます"
            ),
        ));
    }
    let outcome = async {
        let d = download(link, url).await?;
        if let Some(problem) = problems(&d.parsed, true).into_iter().next() {
            return Err(fetch_failed(problem));
        }
        Ok(d.parsed)
    }
    .await;
    let parsed = match outcome {
        Ok(p) => p,
        Err(e) => {
            if e.code != ErrorCode::ProviderEgressBlocked {
                record_failure(link, id, &e).await;
            }
            return Err(e);
        }
    };
    if parsed.import_hash() == current.content_sha256 {
        return record(
            link,
            id,
            true,
            tr!(
                "The content has not changed",
                "內容沒有變更",
                "内容に変更はありません"
            ),
        )
        .await;
    }
    let entries = parsed.stats.entries;
    let revision = current.meta.revision;
    let first = current.awaiting_content();
    let list = with_content(current, &parsed);
    match put(link, list, Some(revision), Some(parsed)).await {
        Ok(_) => record(link, id, true, content_message(entries, first)).await,
        Err(e) => {
            // e.g. the new content covers an address a connection needs: refused, stale.
            record_failure(link, id, &e).await;
            Err(e)
        }
    }
}

/// What one pass of the schedule did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Lists that were due.
    pub due: usize,
    /// Refreshes tried (all due lists, or none while the egress cannot carry them).
    pub tried: usize,
    /// Why nothing was tried although lists were due.
    pub waiting: Option<Text>,
}

/// Refresh the URL lists whose automatic refresh is due, one at a time.
///
/// While the Provider
/// egress cannot carry a download nothing is tried and nothing is recorded: the lists wait, and
/// the first pass after the egress is up downloads them.
///
/// # Errors
///
/// The manager's error when the lists cannot be read; a failed refresh of one list is only
/// logged.
pub async fn refresh_due(link: &ManagerLink) -> Result<Pass, ApiError> {
    let (all, reason) = views_waiting(link).await?;
    let now = Timestamp::now();
    let due: Vec<&BlocklistView> = all
        .iter()
        .filter(|v| v.next_refresh_at.is_some_and(|at| at <= now))
        .collect();
    let mut pass = Pass {
        due: due.len(),
        ..Pass::default()
    };
    if let Some(reason) = reason.filter(|_| due.iter().any(|v| v.waiting.is_some())) {
        pass.waiting = Some(reason);
        return Ok(pass);
    }
    for v in due {
        let id = v.blocklist.id;
        pass.tried += 1;
        match refresh(link, id).await {
            Ok(_) => tracing::info!(blocklist = %id, "blocklist refreshed"),
            Err(e) => {
                tracing::warn!(blocklist = %id, error = %e.message.en, "blocklist refresh failed; last good content kept");
            }
        }
    }
    Ok(pass)
}

/// Refresh URL sources whose automatic refresh is due, forever.
pub async fn auto_refresh(link: Arc<ManagerLink>) {
    let mut tick = tokio::time::interval(SCHEDULE_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut waited: Option<Text> = None;
    loop {
        tick.tick().await;
        match refresh_due(&link).await {
            Ok(pass) => {
                if pass.waiting.is_some() && pass.waiting != waited {
                    tracing::info!(
                        lists = pass.due,
                        reason = pass.waiting.as_ref().map_or("", |t| t.en.as_str()),
                        "blocklists wait for the Provider egress"
                    );
                }
                waited = pass.waiting;
            }
            Err(e) => {
                tracing::debug!(error = %e.message.en, "blocklists not read; next pass later");
            }
        }
    }
}

/// `GET /v1/blocklists/builtin`.
///
/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn builtin(link: &ManagerLink) -> Result<Vec<BuiltinBlocklistState>, ApiError> {
    match link.call(Call::BuiltinBlocklists).await? {
        Reply::BuiltinBlocklists(v) => Ok(v),
        _ => Err(ApiError::internal()),
    }
}

/// `POST /v1/blocklists/builtin/{key}/restore`: bring back a built-in list the user deleted. It
/// waits for its first download like a new one (the next scheduled pass).
///
/// # Errors
///
/// The manager's error (no such built-in list), or an internal error when it answers out of
/// contract.
pub async fn restore(link: &ManagerLink, key: &str) -> Result<BlocklistView, ApiError> {
    match link
        .call(Call::RestoreBuiltinBlocklist { key: key.into() })
        .await?
    {
        Reply::Blocklist(v) => Ok(annotated(link, *v).await),
        _ => Err(ApiError::internal()),
    }
}

/// Forget the lock of a deleted list.
pub fn forget(id: BlocklistId) {
    LOCKS.lock().remove(&id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commit_must_match_its_preview() {
        let parsed = parse(b"1.2.3.4\n").unwrap();
        assert!(accept(&parsed, false, &parsed.import_hash()).is_ok());
        let other = parse(b"5.6.7.8\n").unwrap();
        assert_eq!(
            accept(&parsed, false, &other.import_hash())
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
        let empty = parse(b"").unwrap();
        assert_eq!(
            accept(&empty, false, &empty.import_hash())
                .unwrap_err()
                .code,
            ErrorCode::ValidationFailed
        );
        assert_eq!(
            parse_error(&BlocklistError::Compressed("gzip")).code,
            ErrorCode::UnsupportedMediaType
        );
    }
}
