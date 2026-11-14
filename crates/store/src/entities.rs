//! Typed, revisioned configuration entities.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use vpn_domain::{
    AppSpec, Blocklist, DnsProfile, EntityMeta, ForwardBinding, GatewaySpec, InstanceSpec,
    MAX_SAFE_INTEGER, ProviderAccount, RuntimeProfile, SecurityProfile, SshDownloadJob, SshHost,
    Text, Timestamp, TransportProfile, TransportRef, TransportSettings, tr,
};

use crate::error::StoreError;

/// A configuration entity stored as immutable JSON revisions.
pub trait Entity: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    const KIND: &'static str;
    /// Human name used in "still referenced by ..." errors.
    fn label() -> Text;
    fn id_string(&self) -> String;
    fn meta(&self) -> &EntityMeta;
    fn meta_mut(&mut self) -> &mut EntityMeta;
    /// Ids of other entities this one references, as `(kind, id)`.
    fn references(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

macro_rules! entity {
    ($t:ty, $kind:literal, $label:expr, |$s:ident| $refs:expr) => {
        impl Entity for $t {
            const KIND: &'static str = $kind;
            fn label() -> Text {
                $label.into()
            }
            fn id_string(&self) -> String {
                self.id.to_string()
            }
            fn meta(&self) -> &EntityMeta {
                &self.meta
            }
            fn meta_mut(&mut self) -> &mut EntityMeta {
                &mut self.meta
            }
            fn references(&$s) -> Vec<(&'static str, String)> {
                $refs
            }
        }
    };
}

entity!(
    RuntimeProfile,
    "runtime_profile",
    tr!("WireGuard profile", "WireGuard 設定", "WireGuard 設定"),
    |self| Vec::new()
);
entity!(
    DnsProfile,
    "dns_profile",
    tr!("DNS profile", "DNS 設定", "DNS 設定"),
    |self| Vec::new()
);
entity!(
    SecurityProfile,
    "security_profile",
    tr!("security profile", "安全設定", "セキュリティ設定"),
    |self| self
        .blocklists
        .iter()
        .map(|b| ("blocklist", b.to_string()))
        .collect()
);
entity!(
    Blocklist,
    "blocklist",
    tr!("IP blocklist", "IP 封鎖清單", "IP ブロックリスト"),
    |self| Vec::new()
);
entity!(
    TransportProfile,
    "transport_profile",
    tr!("transport profile", "傳輸設定", "トランスポート設定"),
    |self| match &self.settings {
        TransportSettings::Fixed { .. } => Vec::new(),
        // The saved profiles its ranges name; a built-in one is part of the program.
        TransportSettings::Auto { bands } => bands
            .iter()
            .filter_map(|b| saved_transport(&b.profile))
            .collect(),
    }
);
entity!(InstanceSpec, "instance", "Instance", |self| {
    let mut v = vec![("runtime_profile", self.profile_id.to_string())];
    if let Some(d) = self.dns_profile_id {
        v.push(("dns_profile", d.to_string()));
    }
    if let Some(s) = self.security_profile_id {
        v.push(("security_profile", s.to_string()));
    }
    v.extend(saved_transport(&self.transport));
    v
});
entity!(GatewaySpec, "gateway", "Gateway", |self| vec![(
    "instance",
    self.instance_id.to_string()
)]);
entity!(
    AppSpec,
    "app",
    tr!("managed app", "受管 App", "管理対象アプリ"),
    |self| {
        let mut v = vec![("instance", self.instance_id.to_string())];
        if let Some(g) = self.gateway_id {
            v.push(("gateway", g.to_string()));
        }
        v
    }
);
entity!(
    SshHost,
    "ssh_host",
    tr!("SSH host", "SSH 主機", "SSH ホスト"),
    |self| self
        .gateway_id
        .map_or_default(|g| vec![("gateway", g.to_string())])
);
entity!(
    ProviderAccount,
    "provider_account",
    tr!("Provider account", "Provider 帳號", "Provider アカウント"),
    |self| Vec::new()
);
entity!(
    SshDownloadJob,
    "ssh_download_job",
    tr!("SSH download", "SSH 下載", "SSH ダウンロード"),
    |self| vec![("gateway", self.gateway_id.to_string())]
);
entity!(
    ForwardBinding,
    "forward_binding",
    tr!("port forward", "轉發", "ポート転送"),
    |self| vec![
        ("instance", self.instance_id.to_string()),
        ("app", self.target_app_id.to_string())
    ]
);

/// The stored transport profile a reference names, as an entity reference; `None` for a
/// built-in one.
fn saved_transport(reference: &TransportRef) -> Option<(&'static str, String)> {
    match reference {
        TransportRef::Profile { id } => Some(("transport_profile", id.to_string())),
        TransportRef::Builtin { .. } => None,
    }
}

/// How a referrer holds the id: one field, an array of ids, or an array of objects each holding
/// it at the given path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Holds {
    One,
    Many,
    Each(&'static str),
}

/// Which kinds may reference a kind (for delete protection), as `(kind, json path, how)`; a
/// referrer is named by [`referrer_label`].
fn referrers(kind: &str) -> &'static [(&'static str, &'static str, Holds)] {
    use Holds::{Each, Many, One};
    match kind {
        "runtime_profile" => &[("instance", "$.profile_id", One)],
        "dns_profile" => &[("instance", "$.dns_profile_id", One)],
        "security_profile" => &[("instance", "$.security_profile_id", One)],
        "transport_profile" => &[
            ("instance", "$.transport.id", One),
            (
                "transport_profile",
                "$.settings.bands",
                Each("$.profile.id"),
            ),
        ],
        "blocklist" => &[("security_profile", "$.blocklists", Many)],
        "instance" => &[
            ("gateway", "$.instance_id", One),
            ("app", "$.instance_id", One),
            ("forward_binding", "$.instance_id", One),
        ],
        "gateway" => &[
            ("app", "$.gateway_id", One),
            ("ssh_host", "$.gateway_id", One),
            ("ssh_download_job", "$.gateway_id", One),
        ],
        "app" => &[("forward_binding", "$.target_app_id", One)],
        "provider_account" => &[("runtime_profile", "$.source.account_id", One)],
        _ => &[],
    }
}

/// What a person calls a referrer kind of [`referrers`] in an `InUse` message.
fn referrer_label(kind: &str) -> Text {
    match kind {
        "instance" => tr!("connection", "連線", "接続"),
        "transport_profile" => tr!("transport profile", "傳輸設定", "トランスポート設定"),
        "security_profile" => tr!("security profile", "安全設定", "セキュリティ設定"),
        "gateway" => tr!("Gateway", "代理埠", "ゲートウェイ"),
        "app" => tr!("managed app", "受管 App", "管理対象アプリ"),
        "forward_binding" => tr!("port forward", "轉發", "ポート転送"),
        "ssh_host" => tr!("SSH host", "SSH 主機", "SSH ホスト"),
        "ssh_download_job" => tr!("SSH download", "SSH 下載", "SSH ダウンロード"),
        "runtime_profile" => tr!("WireGuard profile", "WireGuard 設定", "WireGuard 設定"),
        other => Text::verbatim(other),
    }
}

pub fn head_revision(conn: &Connection, kind: &str, id: &str) -> Result<Option<u64>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT revision FROM entity_heads WHERE kind = ?1 AND id = ?2",
            params![kind, id],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .map(i64::cast_unsigned))
}

fn exists(conn: &Connection, kind: &str, id: &str) -> Result<bool, StoreError> {
    Ok(head_revision(conn, kind, id)?.is_some())
}

fn check_references(conn: &Connection, refs: &[(&'static str, String)]) -> Result<(), StoreError> {
    for (kind, id) in refs {
        if !exists(conn, kind, id)? {
            return Err(StoreError::InvalidState(tr!(
                "The referenced {kind} does not exist",
                "參照的 {kind} 不存在",
                "参照先の {kind} が存在しません"
            )));
        }
    }
    Ok(())
}

pub fn insert<E: Entity>(conn: &mut Connection, e: E) -> Result<E, StoreError> {
    let tx = conn.transaction()?;
    let e = insert_in(&tx, e)?;
    tx.commit()?;
    Ok(e)
}

/// [`insert`] inside a transaction the caller owns (several entities, or an entity and other
/// rows, committed together).
pub fn insert_in<E: Entity>(tx: &Connection, mut e: E) -> Result<E, StoreError> {
    let id = e.id_string();
    if head_revision(tx, E::KIND, &id)?.is_some() {
        return Err(StoreError::InvalidState(tr!(
            "Data with the same id already exists",
            "已存在相同 id 的資料",
            "同じ id のデータがすでに存在します"
        )));
    }
    check_references(tx, &e.references())?;
    let now = Timestamp::now();
    *e.meta_mut() = EntityMeta {
        revision: 1,
        created_at: now,
        updated_at: now,
    };
    let body = serde_json::to_string(&e)?;
    tx.execute(
        "INSERT INTO entity_revisions (kind, id, revision, body, created_at) VALUES (?1, ?2, 1, ?3, ?4)",
        params![E::KIND, id, body, now.to_string()],
    )?;
    tx.execute(
        "INSERT INTO entity_heads (kind, id, revision, created_at, updated_at) VALUES (?1, ?2, 1, ?3, ?3)",
        params![E::KIND, id, now.to_string()],
    )?;
    Ok(e)
}

pub fn update<E: Entity>(conn: &mut Connection, e: E, expected: u64) -> Result<E, StoreError> {
    let tx = conn.transaction()?;
    let e = update_in(&tx, e, expected)?;
    tx.commit()?;
    Ok(e)
}

/// [`update`] inside the caller's transaction.
pub fn update_in<E: Entity>(tx: &Connection, mut e: E, expected: u64) -> Result<E, StoreError> {
    let id = e.id_string();
    let current = head_revision(tx, E::KIND, &id)?.ok_or(StoreError::NotFound)?;
    if current != expected {
        return Err(StoreError::RevisionConflict { expected, current });
    }
    check_references(tx, &e.references())?;
    let created: String = tx.query_row(
        "SELECT created_at FROM entity_heads WHERE kind = ?1 AND id = ?2",
        params![E::KIND, id],
        |r| r.get(0),
    )?;
    let created_at: Timestamp = serde_json::from_value(serde_json::Value::String(created))?;
    let now = Timestamp::now();
    let next = current + 1;
    if next > MAX_SAFE_INTEGER {
        return Err(StoreError::InvalidState("revision overflow".into()));
    }
    *e.meta_mut() = EntityMeta {
        revision: next,
        created_at,
        updated_at: now,
    };
    let body = serde_json::to_string(&e)?;
    tx.execute(
        "INSERT INTO entity_revisions (kind, id, revision, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![E::KIND, id, next.cast_signed(), body, now.to_string()],
    )?;
    tx.execute(
        "UPDATE entity_heads SET revision = ?3, updated_at = ?4 WHERE kind = ?1 AND id = ?2",
        params![E::KIND, id, next.cast_signed(), now.to_string()],
    )?;
    Ok(e)
}

/// Names shown for a referencing entity (most have `name`; SSH hosts an alias, accounts a label).
const DISPLAY_NAME: &str =
    "COALESCE(json_extract(r.body, '$.name'), json_extract(r.body, '$.alias'),
                                    json_extract(r.body, '$.label'), h.id)";
/// Referrers named in an `InUse` message.
const NAMES_SHOWN: usize = 5;

/// Display names of the live `referrer` entities whose `path` holds `id`.
pub fn referencing_names(
    conn: &Connection,
    referrer: &str,
    path: &str,
    holds: Holds,
    id: &str,
    limit: usize,
) -> Result<Vec<String>, StoreError> {
    let filter = match holds {
        Holds::One => "json_extract(r.body, ?2) = ?3".to_string(),
        Holds::Many => {
            "EXISTS (SELECT 1 FROM json_each(r.body, ?2) e WHERE e.value = ?3)".to_string()
        }
        // `inner` is one of this module's own constants, never input.
        Holds::Each(inner) => format!(
            "EXISTS (SELECT 1 FROM json_each(r.body, ?2) e
               WHERE json_extract(e.value, '{inner}') = ?3)"
        ),
    };
    let sql = format!(
        "SELECT {DISPLAY_NAME} FROM entity_heads h JOIN entity_revisions r
           ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision
         WHERE h.kind = ?1 AND {filter} ORDER BY h.created_at, h.id LIMIT ?4"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![referrer, path, id, i64::try_from(limit).unwrap_or(i64::MAX)],
        |r| r.get::<_, String>(0),
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The first kind of stored entity that still references `kind`/`id`: its label and the
/// display names of up to `NAMES_SHOWN + 1` of them.
fn referenced_by(
    conn: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<(Text, Vec<String>)>, StoreError> {
    for (referrer, path, holds) in referrers(kind) {
        let names = referencing_names(conn, referrer, path, *holds, id, NAMES_SHOWN + 1)?;
        if !names.is_empty() {
            return Ok(Some((referrer_label(referrer), names)));
        }
    }
    Ok(None)
}

/// `InUse` with the referrer kind's label (`連線`, `安全設定`…) if any stored entity still
/// references `kind`/`id`.
pub fn unreferenced(conn: &Connection, kind: &str, id: &str) -> Result<(), StoreError> {
    match referenced_by(conn, kind, id)? {
        Some((label, _)) => Err(StoreError::InUse(label)),
        None => Ok(()),
    }
}

/// [`unreferenced`] for a delete the user asked for: the message names the first few
/// referrers (`安全設定「辦公室」、「實驗室」`), so the user knows what to change first.
pub fn unreferenced_named(conn: &Connection, kind: &str, id: &str) -> Result<(), StoreError> {
    let Some((label, names)) = referenced_by(conn, kind, id)? else {
        return Ok(());
    };
    let shown = names
        .iter()
        .take(NAMES_SHOWN)
        .map(|n| tr!("“{n}”", "「{n}」", "「{n}」"))
        .reduce(|a, b| tr!("{a}, {b}", "{a}、{b}", "{a}、{b}"; a = a, b = b))
        .unwrap_or_default();
    Err(StoreError::InUse(if names.len() > NAMES_SHOWN {
        tr!(
            "{label} {shown} and others",
            "{label}{shown} 等",
            "{label}{shown}など";
            label = label,
            shown = shown
        )
    } else {
        tr!(
            "{label} {shown}",
            "{label}{shown}",
            "{label}{shown}";
            label = label,
            shown = shown
        )
    }))
}

pub fn delete<E: Entity>(conn: &mut Connection, id: &str, expected: u64) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    delete_in::<E>(&tx, id, expected)?;
    tx.commit()?;
    Ok(())
}

/// [`delete`] inside a transaction the caller owns.
pub fn delete_in<E: Entity>(tx: &Connection, id: &str, expected: u64) -> Result<(), StoreError> {
    let current = head_revision(tx, E::KIND, id)?.ok_or(StoreError::NotFound)?;
    if current != expected {
        return Err(StoreError::RevisionConflict { expected, current });
    }
    unreferenced_named(tx, E::KIND, id)?;
    tx.execute(
        "DELETE FROM entity_heads WHERE kind = ?1 AND id = ?2",
        params![E::KIND, id],
    )?;
    // Revisions are kept for history/audit of running generations; they are tiny.
    Ok(())
}

pub fn get<E: Entity>(conn: &Connection, id: &str) -> Result<Option<E>, StoreError> {
    let body: Option<String> = conn
        .query_row(
            "SELECT r.body FROM entity_heads h JOIN entity_revisions r
               ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision
             WHERE h.kind = ?1 AND h.id = ?2",
            params![E::KIND, id],
            |r| r.get(0),
        )
        .optional()?;
    body.map(|b| serde_json::from_str(&b).map_err(StoreError::from))
        .transpose()
}

pub fn get_revision<E: Entity>(
    conn: &Connection,
    id: &str,
    revision: u64,
) -> Result<Option<E>, StoreError> {
    let body: Option<String> = conn
        .query_row(
            "SELECT body FROM entity_revisions WHERE kind = ?1 AND id = ?2 AND revision = ?3",
            params![E::KIND, id, revision.cast_signed()],
            |r| r.get(0),
        )
        .optional()?;
    body.map(|b| serde_json::from_str(&b).map_err(StoreError::from))
        .transpose()
}

pub fn list<E: Entity>(conn: &Connection) -> Result<Vec<E>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT r.body FROM entity_heads h JOIN entity_revisions r
           ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision
         WHERE h.kind = ?1 ORDER BY h.created_at, h.id",
    )?;
    let rows = stmt.query_map(params![E::KIND], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(serde_json::from_str(&row?)?);
    }
    Ok(out)
}
