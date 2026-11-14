//! Security records: blocklist content (stored apart from the revisioned blocklist entity), the
//! refresh state of URL blocklists, the built-in lists, the overlay revision counter, and
//! auto-bans.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use vpn_domain::blocklist::MAX_LISTS_PER_PROFILE;
use vpn_domain::builtin_blocklists::{BUILTIN_BLOCKLISTS, BuiltinBlocklist, builtin};
use vpn_domain::ipset::{IpRangeSet, MAX_ENCODED_BYTES};
use vpn_domain::{
    Ban, BanId, Blocklist, BlocklistId, BlocklistRefreshState, BlocklistSource, BlocklistStats,
    BuiltinBlocklistState, EntityMeta, InstanceId, NamedRef, SecurityProfile, Text, Timestamp, tr,
};

use crate::Store;
use crate::entities;
use crate::error::StoreError;

/// Control schema step 11 (security defaults): which built-in list each catalogue key created,
/// and whether the user deleted it — a deleted one is remembered and never created again on its
/// own (only an explicit restore brings it back).
const BUILTIN_TABLE: &str = r"
CREATE TABLE builtin_blocklists (
    key          TEXT PRIMARY KEY,
    blocklist_id TEXT UNIQUE,
    created_at   TEXT NOT NULL,
    deleted_at   TEXT,
    CHECK ((blocklist_id IS NULL) = (deleted_at IS NOT NULL))
) WITHOUT ROWID;
";

/// Event kind of the notes a migration leaves in the event log.
pub const MIGRATION_EVENT: &str = "store.migration";

/// Control schema step 11: the built-in blocklists are created (a list the user already
/// downloads from the same URL becomes the built-in one instead of a second copy), added once
/// to every existing security profile, and auto-ban is turned on in every profile whose history
/// does not show the user turning it off. What it did is written to the event log
/// ([`MIGRATION_EVENT`]): the migration's notes.
pub fn defaults_step(tx: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    tx.execute_batch(BUILTIN_TABLE)?;
    let created = seed_builtin(tx)?;
    let builtin_ids: Vec<BlocklistId> = created.iter().map(|c| c.id).collect();
    let mut profiles = Vec::new();
    for (profile, revision) in live_profiles(tx)? {
        let mut next = profile.clone();
        let mut note = serde_json::Map::new();
        note.insert("id".into(), profile.id.to_string().into());
        note.insert("name".into(), profile.name.clone().into());
        // Built-in lists did not exist before: the profile never had the choice. They join
        // (as many as a profile may hold), and the user can unselect them.
        let mut added = Vec::new();
        for id in &builtin_ids {
            if next.blocklists.len() >= MAX_LISTS_PER_PROFILE {
                note.insert(
                    "blocklists_not_added".into(),
                    "MAX_LISTS_PER_PROFILE".into(),
                );
                break;
            }
            if !next.blocklists.contains(id) {
                next.blocklists.push(*id);
                added.push(id.to_string());
            }
        }
        if !added.is_empty() {
            note.insert("blocklists_added".into(), added.into());
        }
        // Auto-ban: on now, unless the user turned it off. A stored `false` with no `true`
        // anywhere in the profile's history cannot be told apart from the old default (the
        // editor started with it off): that one is turned on, and the note says so.
        if !profile.auto_ban.enabled {
            let turned_off: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM entity_revisions
                                 WHERE kind = 'security_profile' AND id = ?1
                                   AND json_extract(body, '$.auto_ban.enabled') = 1)",
                params![profile.id.to_string()],
                |r| r.get(0),
            )?;
            if turned_off {
                note.insert(
                    "auto_ban".into(),
                    serde_json::to_value(tr!(
                        "Kept off: an earlier version had it on, and the user turned it off",
                        "保持關閉：較早的版本曾經開啟，是使用者關閉的",
                        "オフのまま：以前のバージョンでオンになっていて、ユーザーがオフにしました"
                    ))?,
                );
            } else {
                next.auto_ban.enabled = true;
                note.insert(
                    "auto_ban".into(),
                    serde_json::to_value(tr!(
                        "Turned on: it was never on, so the old default cannot be told apart from the user's choice; on by the new default",
                        "已開啟：從未開啟過，無法分辨是舊的預設還是使用者的選擇，依新的預設開啟",
                        "オンにしました：一度もオンになったことがなく、以前の既定値かユーザーの選択か区別できないため、新しい既定値でオンにしました"
                    ))?,
                );
            }
        }
        if next != profile {
            entities::update_in(tx, next, revision)?;
        }
        if note.len() > 2 {
            profiles.push(serde_json::Value::Object(note));
        }
    }
    let note = serde_json::json!({
        "step": 11,
        "summary": tr!(
            "Security defaults: created the built-in IP blocklists (in effect once downloaded through the Provider egress) and added them to the existing security profiles; auto-ban is on by default and stays off where the user turned it off",
            "安全性預設：建立內建 IP 封鎖清單（經 Provider 出口下載後才生效）、加入既有的安全設定；自動封鎖預設開啟，使用者曾經關閉的保持關閉",
            "セキュリティの既定値：組み込みの IP ブロックリストを作成し（Provider 出口経由でダウンロードされてから有効）、既存のセキュリティ設定に追加しました。自動ブロックは既定でオンで、ユーザーがオフにした設定はオフのままです"
        ),
        "builtin_blocklists": created.iter().map(|c| serde_json::json!({
            "key": c.key, "id": c.id.to_string(), "adopted": c.adopted,
        })).collect::<Vec<_>>(),
        "security_profiles": profiles,
    });
    append_event_in(tx, MIGRATION_EVENT, &note)?;
    Ok(())
}

/// On every start: create the built-in lists a later release added to the catalogue. A list the
/// user deleted is not created again (its row stays, marked deleted). The default security policy
/// picks a new list up by itself; security profiles keep the selection the user made.
pub fn ensure_builtin_blocklists(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    let created = seed_builtin(&tx)?;
    let moved = follow_catalogue(&tx)?;
    if !created.is_empty() || !moved.is_empty() {
        append_event_in(
            &tx,
            MIGRATION_EVENT,
            &serde_json::json!({
                "summary": tr!(
                    "The built-in IP blocklists were updated from the program's built-in catalogue",
                    "內建 IP 封鎖清單依程式內建的清單目錄更新",
                    "組み込みの IP ブロックリストをプログラム組み込みのリストカタログに合わせて更新しました"
                ),
                "builtin_blocklists": created.iter().map(|c| serde_json::json!({
                    "key": c.key, "id": c.id.to_string(), "adopted": c.adopted,
                })).collect::<Vec<_>>(),
                "sources_moved": moved,
            }),
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// A built-in list created (or adopted) by [`seed_builtin`].
struct Seeded {
    key: &'static str,
    id: BlocklistId,
    /// An existing list of the user with the same URL became the built-in one.
    adopted: bool,
}

/// Create every catalogue entry that has no row yet (never one the user deleted).
fn seed_builtin(c: &Connection) -> Result<Vec<Seeded>, StoreError> {
    let known: HashSet<String> = {
        let mut stmt = c.prepare("SELECT key FROM builtin_blocklists")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut out = Vec::new();
    for b in BUILTIN_BLOCKLISTS {
        if !known.contains(b.key) {
            let (list, adopted) = create_builtin(c, b)?;
            out.push(Seeded {
                key: b.key,
                id: list.id,
                adopted,
            });
        }
    }
    Ok(out)
}

/// Create the list of catalogue entry `b` — no content yet: it waits for its first download —
/// and remember it. A live list of the user's that already downloads `b.url` becomes the built-in
/// one instead (a new revision; its name, interval, content and state stay), so the same source
/// is never fetched twice.
fn create_builtin(c: &Connection, b: &BuiltinBlocklist) -> Result<(Blocklist, bool), StoreError> {
    let mine = entities::list::<Blocklist>(c)?.into_iter().find(|l| {
        l.builtin.is_none() && matches!(&l.source, BlocklistSource::Url { url, .. } if url == b.url)
    });
    let now = Timestamp::now();
    let (list, adopted) = if let Some(l) = mine {
        let revision = l.meta.revision;
        let adopted = Blocklist {
            builtin: Some(b.key.into()),
            ..l
        };
        (entities::update_in(c, adopted, revision)?, true)
    } else {
        let empty = IpRangeSet::new();
        let list = Blocklist {
            id: BlocklistId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: now,
                updated_at: now,
            },
            name: b.list_name(),
            source: BlocklistSource::Url {
                url: b.url.into(),
                refresh_hours: Some(b.refresh_hours),
            },
            stats: BlocklistStats {
                v6_addresses: "0".into(),
                parsed_bytes: u32::try_from(empty.encoded_len()).unwrap_or(u32::MAX),
                ..BlocklistStats::default()
            },
            content_sha256: empty.digest(),
            content_updated_at: now,
            invalid_lines: Vec::new(),
            builtin: Some(b.key.into()),
            enabled: true,
        };
        let list = entities::insert_in(c, list)?;
        put_content(c, &list, list.meta.revision, &empty)?;
        (list, false)
    };
    c.execute(
        "INSERT INTO builtin_blocklists (key, blocklist_id, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (key) DO UPDATE SET blocklist_id = excluded.blocklist_id,
            created_at = excluded.created_at, deleted_at = NULL",
        params![b.key, list.id.to_string(), now.to_string()],
    )?;
    Ok((list, adopted))
}

/// A built-in list downloads from its catalogue entry's URL: when a later release moves a source,
/// the stored list moves with it (a new revision; the interval, name and state the user chose
/// stay). The keys of the lists moved.
fn follow_catalogue(c: &Connection) -> Result<Vec<&'static str>, StoreError> {
    let mut moved = Vec::new();
    for list in entities::list::<Blocklist>(c)? {
        let Some(b) = list.builtin.as_deref().and_then(builtin) else {
            continue;
        };
        let refresh_hours = match &list.source {
            BlocklistSource::Url { url, .. } if url == b.url => continue,
            BlocklistSource::Url { refresh_hours, .. } => *refresh_hours,
            BlocklistSource::Upload => Some(b.refresh_hours),
        };
        let revision = list.meta.revision;
        let next = Blocklist {
            source: BlocklistSource::Url {
                url: b.url.into(),
                refresh_hours,
            },
            ..list
        };
        entities::update_in(c, next, revision)?;
        moved.push(b.key);
    }
    Ok(moved)
}

/// Every live security profile with its head revision.
fn live_profiles(c: &Connection) -> Result<Vec<(SecurityProfile, u64)>, StoreError> {
    Ok(entities::list::<SecurityProfile>(c)?
        .into_iter()
        .map(|p| {
            let revision = p.meta.revision;
            (p, revision)
        })
        .collect())
}

/// Append to the bounded event log inside the caller's transaction.
fn append_event_in(c: &Connection, kind: &str, body: &serde_json::Value) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO events (at, kind, entity_id, body) VALUES (?1, ?2, NULL, ?3)",
        params![Timestamp::now().to_string(), kind, body.to_string()],
    )?;
    Ok(())
}

fn ts(ms: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_unix_millis(ms).ok_or_else(|| StoreError::Corrupt("timestamp".into()))
}

fn parse_ts(s: String) -> Result<Timestamp, StoreError> {
    Ok(serde_json::from_value(serde_json::Value::String(s))?)
}

/// Store the content row of `list` (whose entity revision is `revision`) and drop older ones.
fn put_content(
    tx: &Connection,
    list: &Blocklist,
    revision: u64,
    set: &IpRangeSet,
) -> Result<(), StoreError> {
    let bytes = set.encode();
    let sha = hex::encode(Sha256::digest(&bytes));
    if sha != list.content_sha256 {
        return Err(StoreError::InvalidState(tr!(
            "The blocklist content does not match its hash",
            "封鎖清單內容與它的雜湊不符",
            "ブロックリストの内容がハッシュと一致しません"
        )));
    }
    let id = list.id.to_string();
    tx.execute(
        "INSERT INTO blocklist_content (blocklist_id, revision, sha256, ranges, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            revision.cast_signed(),
            sha,
            bytes,
            Timestamp::now().to_string()
        ],
    )?;
    tx.execute(
        "DELETE FROM blocklist_content WHERE blocklist_id = ?1 AND revision < ?2",
        params![id, revision.cast_signed()],
    )?;
    Ok(())
}

fn refresh_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RefreshRow> {
    Ok(RefreshRow {
        id: r.get(0)?,
        attempted_at: r.get(1)?,
        ok: r.get(2)?,
        message: r.get(3)?,
        succeeded_at: r.get(4)?,
        stale_since: r.get(5)?,
    })
}

struct RefreshRow {
    id: String,
    attempted_at: String,
    ok: bool,
    message: Option<String>,
    succeeded_at: Option<String>,
    stale_since: Option<String>,
}

impl RefreshRow {
    fn into_state(self) -> Result<(BlocklistId, BlocklistRefreshState), StoreError> {
        Ok((
            self.id
                .parse()
                .map_err(|_| StoreError::Corrupt("blocklist id".into()))?,
            BlocklistRefreshState {
                attempted_at: parse_ts(self.attempted_at)?,
                ok: self.ok,
                message: self.message.map(crate::text_column::from_column),
                succeeded_at: self.succeeded_at.map(parse_ts).transpose()?,
                stale_since: self.stale_since.map(parse_ts).transpose()?,
            },
        ))
    }
}

const BAN_COLUMNS: &str =
    "id, instance_id, source, reason, security_profile_id, security_profile_revision,
     policy_revision, generation, created_ms, expires_ms";

type BanRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    i64,
    i64,
);

fn ban_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BanRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
    ))
}

fn ban_of(row: BanRow) -> Result<Ban, StoreError> {
    let (id, instance, source, reason, sp, spr, policy, generation, created, expires) = row;
    let corrupt = |what: &str| StoreError::Corrupt(format!("ban {what}"));
    Ok(Ban {
        id: id.parse().map_err(|_| corrupt("id"))?,
        instance_id: instance.parse().map_err(|_| corrupt("instance"))?,
        // Older records may hold a whole IPv6 address; a ban covers its /64.
        source: source
            .parse()
            .map(vpn_domain::validation::ban_scope)
            .map_err(|_| corrupt("source"))?,
        reason: crate::text_column::from_column(reason),
        security_profile_id: sp
            .map(|s| s.parse().map_err(|_| corrupt("security profile")))
            .transpose()?,
        security_profile_revision: spr.map(i64::cast_unsigned),
        policy_revision: policy.cast_unsigned(),
        generation: generation.cast_unsigned(),
        created_at: ts(created)?,
        expires_at: ts(expires)?,
    })
}

fn read_bans(
    c: &Connection,
    filter: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<Ban>, StoreError> {
    let sql = format!("SELECT {BAN_COLUMNS} FROM bans WHERE {filter} ORDER BY created_ms DESC, id");
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map(args, ban_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(ban_of(row?)?);
    }
    Ok(out)
}

/// What [`Store::add_ban`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanAdded {
    /// Stored as a new active ban.
    New(Ban),
    /// The source was already banned: its expiry and reason were renewed.
    Renewed(Ban),
    /// The Instance already has `max_bans` active bans: not stored.
    Full,
}

impl Store {
    // -----------------------------------------------------------------------------------------
    // Blocklists
    // -----------------------------------------------------------------------------------------

    /// Create a blocklist and its content in one transaction. `list.content_sha256` must be the
    /// digest of `set`.
    ///
    /// # Errors
    ///
    /// `InvalidState` when the id exists already or `set` does not match `content_sha256`; `Busy`
    /// when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn create_blocklist(
        &self,
        list: Blocklist,
        set: IpRangeSet,
    ) -> Result<Blocklist, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let list = entities::insert_in(&tx, list)?;
                put_content(&tx, &list, list.meta.revision, &set)?;
                tx.commit()?;
                Ok(list)
            })
            .await
    }

    /// Store a new revision of a blocklist; with `set`, its content changes in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown list, `InvalidState` when the digest changes without new content
    /// (or does not match it), `RevisionConflict` when `expected_revision` is stale; `Busy` when
    /// the write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding`
    /// when the transaction fails.
    pub async fn update_blocklist(
        &self,
        list: Blocklist,
        expected_revision: u64,
        set: Option<IpRangeSet>,
    ) -> Result<Blocklist, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let current: Option<Blocklist> = entities::get(&tx, &list.id.to_string())?;
                let current = current.ok_or(StoreError::NotFound)?;
                if set.is_none() && current.content_sha256 != list.content_sha256 {
                    return Err(StoreError::InvalidState(tr!(
                        "The blocklist content can only change together with new content",
                        "封鎖清單內容只能和新內容一起變更",
                        "ブロックリストの内容は新しい内容と一緒にしか変更できません"
                    )));
                }
                let list = entities::update_in(&tx, list, expected_revision)?;
                if let Some(set) = &set {
                    put_content(&tx, &list, list.meta.revision, set)?;
                }
                tx.commit()?;
                Ok(list)
            })
            .await
    }

    /// The built-in catalogue, each entry with the list it created or when the user deleted it.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed stored list id; `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the read or a row's decoding fails.
    pub async fn builtin_blocklists(&self) -> Result<Vec<BuiltinBlocklistState>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT key, blocklist_id, deleted_at FROM builtin_blocklists")?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })?;
                let mut known = HashMap::new();
                for row in rows {
                    let (key, id, deleted) = row?;
                    known.insert(key, (id, deleted));
                }
                BUILTIN_BLOCKLISTS
                    .iter()
                    .map(|b| {
                        let (id, deleted) = known.remove(b.key).unwrap_or_default();
                        Ok(BuiltinBlocklistState {
                            info: b.into(),
                            blocklist_id: id
                                .map(|i| {
                                    i.parse().map_err(|_| {
                                        StoreError::Corrupt("built-in blocklist id".into())
                                    })
                                })
                                .transpose()?,
                            deleted_at: deleted.map(parse_ts).transpose()?,
                        })
                    })
                    .collect()
            })
            .await
    }

    /// Bring back a built-in list the user deleted: created afresh, waiting for its first
    /// download. `InvalidState` while it exists, `NotFound` for a key the catalogue lacks.
    ///
    /// # Errors
    ///
    /// `NotFound` for a key the catalogue lacks, `InvalidState` while the list exists; `Busy` when
    /// the write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding`
    /// when the transaction fails.
    pub async fn restore_builtin_blocklist(&self, key: String) -> Result<Blocklist, StoreError> {
        self.control
            .write(move |c| {
                let b = builtin(&key).ok_or(StoreError::NotFound)?;
                let tx = c.transaction()?;
                let present: Option<Option<String>> = tx
                    .query_row(
                        "SELECT blocklist_id FROM builtin_blocklists WHERE key = ?1",
                        params![b.key],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(Some(_)) = present {
                    return Err(StoreError::InvalidState(tr!(
                        "The built-in list “{name}” is still there; there is nothing to restore",
                        "內建清單「{name}」仍在，不需要還原",
                        "組み込みリスト「{name}」はまだ存在するため、復元は不要です";
                        name = b.name()
                    )));
                }
                let (list, _) = create_builtin(&tx, b)?;
                tx.commit()?;
                Ok(list)
            })
            .await
    }

    /// Delete a blocklist no security profile uses (`InUse` names them), with its content and
    /// refresh state. A built-in list is remembered as deleted: it is not created again.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown list, `RevisionConflict` when `expected_revision` is stale,
    /// `InUse` naming the security profiles that use it; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn delete_blocklist(
        &self,
        id: BlocklistId,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let tx = c.transaction()?;
                let current =
                    entities::head_revision(&tx, "blocklist", &ids)?.ok_or(StoreError::NotFound)?;
                if current != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current,
                    });
                }
                entities::unreferenced_named(&tx, "blocklist", &ids)?;
                tx.execute(
                    "DELETE FROM entity_heads WHERE kind = 'blocklist' AND id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM blocklist_content WHERE blocklist_id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM blocklist_refresh WHERE blocklist_id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "UPDATE builtin_blocklists SET blocklist_id = NULL, deleted_at = ?2
                      WHERE blocklist_id = ?1",
                    params![ids, Timestamp::now().to_string()],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// The content of a live blocklist, checked against the digest its record names.
    ///
    /// # Errors
    ///
    /// `Corrupt` when the stored content does not match its digest or does not decode; `Closed`
    /// once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's decoding
    /// fails.
    pub async fn blocklist_set(&self, id: BlocklistId) -> Result<Option<IpRangeSet>, StoreError> {
        self.control
            .read(move |c| {
                let row: Option<(String, Vec<u8>, String)> = c
                    .query_row(
                        "SELECT b.sha256, b.ranges, json_extract(r.body, '$.content_sha256')
                           FROM blocklist_content b
                           JOIN entity_heads h ON h.kind = 'blocklist' AND h.id = b.blocklist_id
                           JOIN entity_revisions r
                             ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision
                          WHERE b.blocklist_id = ?1
                          ORDER BY b.revision DESC LIMIT 1",
                        params![id.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((sha, bytes, named)) = row else {
                    return Ok(None);
                };
                if sha != named || hex::encode(Sha256::digest(&bytes)) != sha {
                    return Err(StoreError::Corrupt(format!("blocklist {id} content")));
                }
                IpRangeSet::decode(&bytes, MAX_ENCODED_BYTES)
                    .map(Some)
                    .map_err(|e| StoreError::Corrupt(format!("blocklist {id} content: {e}")))
            })
            .await
    }

    /// Record a refresh attempt of a URL blocklist. A failure keeps the content and marks it
    /// stale from the first failure after the last success.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown list; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn record_blocklist_refresh(
        &self,
        id: BlocklistId,
        ok: bool,
        message: Option<Text>,
    ) -> Result<BlocklistRefreshState, StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let message = message.as_ref().map(crate::text_column::to_column);
                let tx = c.transaction()?;
                if entities::head_revision(&tx, "blocklist", &ids)?.is_none() {
                    return Err(StoreError::NotFound);
                }
                let now = Timestamp::now().to_string();
                let previous: Option<(Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT succeeded_at, stale_since FROM blocklist_refresh WHERE blocklist_id = ?1",
                        params![ids],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let (succeeded, stale_since) = match (ok, previous) {
                    (true, _) => (Some(now.clone()), None),
                    (false, Some((succeeded, Some(since)))) => (succeeded, Some(since)),
                    (false, Some((succeeded, None))) => (succeeded, Some(now.clone())),
                    (false, None) => (None, Some(now.clone())),
                };
                tx.execute(
                    "INSERT INTO blocklist_refresh
                        (blocklist_id, attempted_at, ok, message, succeeded_at, stale_since)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT (blocklist_id) DO UPDATE SET attempted_at = excluded.attempted_at,
                        ok = excluded.ok, message = excluded.message,
                        succeeded_at = excluded.succeeded_at, stale_since = excluded.stale_since",
                    params![ids, now, ok, message, succeeded, stale_since],
                )?;
                let row = tx.query_row(
                    "SELECT blocklist_id, attempted_at, ok, message, succeeded_at, stale_since
                       FROM blocklist_refresh WHERE blocklist_id = ?1",
                    params![ids],
                    refresh_from_row,
                )?;
                tx.commit()?;
                Ok(row.into_state()?.1)
            })
            .await
    }

    /// The refresh state of every URL blocklist.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed stored list id or timestamp; `Closed` once the store has shut
    /// down, and `Sqlite` or `Encoding` when the read or a row's decoding fails.
    pub async fn blocklist_refresh_states(
        &self,
    ) -> Result<HashMap<BlocklistId, BlocklistRefreshState>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT blocklist_id, attempted_at, ok, message, succeeded_at, stale_since
                       FROM blocklist_refresh",
                )?;
                let rows = stmt.query_map([], refresh_from_row)?;
                let mut out = HashMap::new();
                for row in rows {
                    let (id, state) = row?.into_state()?;
                    out.insert(id, state);
                }
                Ok(out)
            })
            .await
    }

    /// The security profiles using each blocklist.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed blocklist reference; `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the read or a row's decoding fails.
    pub async fn blocklist_users(&self) -> Result<HashMap<BlocklistId, Vec<NamedRef>>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT e.value, h.id, json_extract(r.body, '$.name')
                       FROM entity_heads h JOIN entity_revisions r
                         ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision,
                            json_each(r.body, '$.blocklists') e
                      WHERE h.kind = 'security_profile'
                      ORDER BY h.created_at, h.id",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?;
                let mut out: HashMap<BlocklistId, Vec<NamedRef>> = HashMap::new();
                for row in rows {
                    let (list, id, name) = row?;
                    let list: BlocklistId = list
                        .parse()
                        .map_err(|_| StoreError::Corrupt("blocklist reference".into()))?;
                    out.entry(list).or_default().push(NamedRef { id, name });
                }
                Ok(out)
            })
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Overlay revisions
    // -----------------------------------------------------------------------------------------

    /// The next `enforcement_policy_revision`: one counter for every Instance, never reused.
    ///
    /// # Errors
    ///
    /// `Corrupt` when the stored counter is not a number; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn next_policy_revision(&self) -> Result<u64, StoreError> {
        self.control
            .write(|c| {
                let v: String = c.query_row(
                    "INSERT INTO meta (key, value) VALUES ('policy_revision', '1')
                     ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
                     RETURNING value",
                    [],
                    |r| r.get(0),
                )?;
                v.parse()
                    .map_err(|_| StoreError::Corrupt("policy revision".into()))
            })
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Bans
    // -----------------------------------------------------------------------------------------

    /// Record a ban reported by an Instance's worker. An Instance holds at most `max_bans`
    /// active bans; a source already banned is renewed instead of duplicated.
    ///
    /// # Errors
    ///
    /// `NotFound` when the renewed ban cannot be read back, `Corrupt` for a malformed stored ban;
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn add_ban(&self, ban: Ban, max_bans: u32) -> Result<BanAdded, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let instance = ban.instance_id.to_string();
                // Stored by scope: an IPv4 address, or the first address of an IPv6 /64.
                let scope = vpn_domain::validation::ban_scope(ban.source);
                let source = scope.to_string();
                let now = Timestamp::now().unix_millis();
                tx.execute(
                    "DELETE FROM bans WHERE instance_id = ?1 AND source = ?2 AND expires_ms <= ?3",
                    params![instance, source, now],
                )?;
                let existing = read_bans(
                    &tx,
                    "instance_id = ?1 AND source = ?2",
                    &[&instance, &source],
                )?;
                if let Some(old) = existing.into_iter().next() {
                    tx.execute(
                        "UPDATE bans SET reason = ?2, expires_ms = ?3, policy_revision = ?4,
                            generation = ?5 WHERE id = ?1",
                        params![
                            old.id.to_string(),
                            crate::text_column::to_column(&ban.reason),
                            ban.expires_at.unix_millis().max(old.expires_at.unix_millis()),
                            ban.policy_revision.cast_signed(),
                            ban.generation.cast_signed()
                        ],
                    )?;
                    let renewed = read_bans(&tx, "id = ?1", &[&old.id.to_string()])?;
                    tx.commit()?;
                    return renewed
                        .into_iter()
                        .next()
                        .map(BanAdded::Renewed)
                        .ok_or(StoreError::NotFound);
                }
                let active: i64 = tx.query_row(
                    "SELECT count(*) FROM bans WHERE instance_id = ?1 AND expires_ms > ?2",
                    params![instance, now],
                    |r| r.get(0),
                )?;
                if active >= i64::from(max_bans) {
                    return Ok(BanAdded::Full);
                }
                tx.execute(
                    &format!("INSERT INTO bans ({BAN_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"),
                    params![
                        ban.id.to_string(),
                        instance,
                        source,
                        crate::text_column::to_column(&ban.reason),
                        ban.security_profile_id.map(|s| s.to_string()),
                        ban.security_profile_revision.map(u64::cast_signed),
                        ban.policy_revision.cast_signed(),
                        ban.generation.cast_signed(),
                        ban.created_at.unix_millis(),
                        ban.expires_at.unix_millis()
                    ],
                )?;
                tx.commit()?;
                Ok(BanAdded::New(Ban {
                    source: scope,
                    ..ban
                }))
            })
            .await
    }

    /// Active (unexpired) bans, newest first; of one Instance or of all.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed stored ban; `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the read or a row's decoding fails.
    pub async fn bans(&self, instance: Option<InstanceId>) -> Result<Vec<Ban>, StoreError> {
        self.control
            .read(move |c| {
                let now = Timestamp::now().unix_millis();
                instance.map_or_else(
                    || read_bans(c, "expires_ms > ?1", &[&now]),
                    |id| {
                        read_bans(
                            c,
                            "instance_id = ?1 AND expires_ms > ?2",
                            &[&id.to_string(), &now],
                        )
                    },
                )
            })
            .await
    }

    /// Ban `id`, if it is active.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed stored ban; `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the read or a row's decoding fails.
    pub async fn ban(&self, id: BanId) -> Result<Option<Ban>, StoreError> {
        self.control
            .read(move |c| {
                Ok(read_bans(c, "id = ?1", &[&id.to_string()])?
                    .into_iter()
                    .next())
            })
            .await
    }

    /// Lift a ban: the removed row, or `None` when there was none.
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed stored ban; `Busy` when the write queue is full, `Closed` once the
    /// store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn delete_ban(&self, id: BanId) -> Result<Option<Ban>, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let found = read_bans(&tx, "id = ?1", &[&id.to_string()])?
                    .into_iter()
                    .next();
                if found.is_some() {
                    tx.execute("DELETE FROM bans WHERE id = ?1", params![id.to_string()])?;
                }
                tx.commit()?;
                Ok(found)
            })
            .await
    }

    /// Delete expired bans; returns how many went.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn expire_bans(&self) -> Result<usize, StoreError> {
        self.control
            .write(|c| {
                Ok(c.execute(
                    "DELETE FROM bans WHERE expires_ms <= ?1",
                    params![Timestamp::now().unix_millis()],
                )?)
            })
            .await
    }

    /// Keep only the `keep` newest active bans of an Instance (its limit was lowered); returns
    /// how many were deleted.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn trim_bans(&self, instance: InstanceId, keep: u32) -> Result<usize, StoreError> {
        self.control
            .write(move |c| {
                Ok(c.execute(
                    "DELETE FROM bans WHERE instance_id = ?1 AND id NOT IN (
                        SELECT id FROM bans WHERE instance_id = ?1
                         ORDER BY created_ms DESC, id LIMIT ?2)",
                    params![instance.to_string(), i64::from(keep)],
                )?)
            })
            .await
    }
}

/// Whether `ip` is a valid ban source (a unicast address, canonical form).
#[must_use]
pub fn ban_source_ok(ip: IpAddr) -> bool {
    !vpn_domain::validation::is_special(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use vpn_domain::{AutoBanSettings, SecurityProfileId};

    fn meta() -> EntityMeta {
        EntityMeta {
            revision: 1,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        }
    }

    fn profile(name: &str, auto_ban: bool, blocklists: Vec<BlocklistId>) -> SecurityProfile {
        SecurityProfile {
            id: SecurityProfileId::new(),
            meta: meta(),
            name: name.into(),
            allow_private: vec!["10.0.0.0/8".parse().unwrap()],
            blocked_ports: Vec::new(),
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists,
            auto_ban: AutoBanSettings {
                enabled: auto_ban,
                ..AutoBanSettings::default()
            },
        }
    }

    fn head<E: entities::Entity>(c: &Connection, id: &impl ToString) -> E {
        entities::get(c, &id.to_string()).unwrap().unwrap()
    }

    /// Everything the control database holds that the upgrade could touch.
    fn snapshot(c: &Connection) -> (Vec<Blocklist>, Vec<SecurityProfile>, i64, i64) {
        let events: i64 = c
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        let rows: i64 = c
            .query_row("SELECT count(*) FROM builtin_blocklists", [], |r| r.get(0))
            .unwrap();
        (
            entities::list(c).unwrap(),
            entities::list(c).unwrap(),
            events,
            rows,
        )
    }

    /// One built-in list per catalogue entry, each enabled with its URL; those created by the
    /// upgrade (all but `mine`) wait for their first download. Returns their ids in order.
    fn check_builtin_lists(lists: &[Blocklist], mine: BlocklistId) -> Vec<BlocklistId> {
        let mut builtin_ids = Vec::new();
        for b in BUILTIN_BLOCKLISTS {
            let l = lists
                .iter()
                .find(|l| l.builtin.as_deref() == Some(b.key))
                .unwrap();
            assert!(l.enabled);
            assert_matches!(&l.source, BlocklistSource::Url { url, .. } if url == b.url);
            if l.id != mine {
                // Created now: nothing enforced until the first download through the egress.
                assert!(l.awaiting_content());
                assert_eq!(
                    l.source,
                    BlocklistSource::Url {
                        url: b.url.into(),
                        refresh_hours: Some(b.refresh_hours)
                    }
                );
                assert_eq!(l.content_sha256, IpRangeSet::new().digest());
            }
            builtin_ids.push(l.id);
        }
        builtin_ids
    }

    /// The upgrade's migration event names every built-in list and each profile's auto-ban.
    fn check_migration_notes(c: &Connection) {
        // The migration's notes.
        let body: String = c
            .query_row(
                "SELECT body FROM events WHERE kind = ?1",
                params![MIGRATION_EVENT],
                |r| r.get(0),
            )
            .unwrap();
        let note: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(note["step"], 11);
        assert_eq!(
            note["builtin_blocklists"].as_array().unwrap().len(),
            BUILTIN_BLOCKLISTS.len()
        );
        let about = |name: &str| {
            note["security_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .cloned()
                .unwrap()
        };
        assert!(
            about("never")["auto_ban"]["zh-TW"]
                .as_str()
                .unwrap()
                .starts_with("已開啟")
        );
        assert!(
            about("off")["auto_ban"]["zh-TW"]
                .as_str()
                .unwrap()
                .starts_with("保持關閉")
        );
        assert!(about("on")["auto_ban"].is_null());
    }

    #[test]
    fn the_upgrade_creates_the_builtin_lists_and_turns_auto_ban_on_once() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::schema::migrate_control_to(&mut c, 10).unwrap();

        // Before the upgrade: the user downloads Spamhaus DROP themselves, and uses it in one of
        // three profiles: auto-ban never on, on and then turned off by the user, and on.
        let content = IpRangeSet::from_networks(["1.10.16.0/20".parse().unwrap()]);
        let mine = entities::insert_in(
            &c,
            Blocklist {
                id: BlocklistId::new(),
                meta: meta(),
                name: "我的 DROP".into(),
                source: BlocklistSource::Url {
                    url: "https://www.spamhaus.org/drop/drop_v4.json".into(),
                    refresh_hours: Some(12),
                },
                stats: BlocklistStats {
                    entries: 1,
                    ..BlocklistStats::default()
                },
                content_sha256: content.digest(),
                content_updated_at: Timestamp::now(),
                invalid_lines: Vec::new(),
                builtin: None,
                enabled: true,
            },
        )
        .unwrap();
        put_content(&c, &mine, 1, &content).unwrap();
        let never = entities::insert_in(&c, profile("never", false, Vec::new())).unwrap();
        let off = entities::insert_in(&c, profile("off", true, vec![mine.id])).unwrap();
        let off = entities::update_in(
            &c,
            SecurityProfile {
                auto_ban: AutoBanSettings {
                    enabled: false,
                    ..AutoBanSettings::default()
                },
                ..off
            },
            1,
        )
        .unwrap();
        let on = entities::insert_in(&c, profile("on", true, Vec::new())).unwrap();

        crate::schema::migrate_control(&mut c).unwrap();
        let version: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, crate::schema::CONTROL_VERSION);

        // One list per catalogue entry; the user's own download of the same URL became the
        // built-in one (its name, interval and content stay) instead of a second copy.
        let lists: Vec<Blocklist> = entities::list(&c).unwrap();
        assert_eq!(lists.len(), BUILTIN_BLOCKLISTS.len());
        let adopted: Blocklist = head(&c, &mine.id);
        assert_eq!(adopted.builtin.as_deref(), Some("spamhaus-drop-v4"));
        assert_eq!(adopted.name, "我的 DROP");
        assert_eq!(adopted.meta.revision, 2);
        assert_eq!(adopted.content_sha256, content.digest());
        let builtin_ids = check_builtin_lists(&lists, mine.id);

        // Every profile gets the built-in lists once (no duplicate of one it had); auto-ban is on,
        // except where the history shows the user turning it off.
        let never: SecurityProfile = head(&c, &never.id);
        assert!(never.auto_ban.enabled);
        assert_eq!(never.meta.revision, 2);
        assert_eq!(never.blocklists, builtin_ids);
        let off: SecurityProfile = head(&c, &off.id);
        assert!(!off.auto_ban.enabled, "the user turned it off");
        assert_eq!(off.meta.revision, 3);
        assert_eq!(off.blocklists.len(), builtin_ids.len());
        assert_eq!(off.blocklists[0], mine.id, "the user's order first");
        let on: SecurityProfile = head(&c, &on.id);
        assert!(on.auto_ban.enabled);
        assert_eq!(on.allow_private, vec!["10.0.0.0/8".parse().unwrap()]);

        check_migration_notes(&c);

        // Opening again changes nothing: no list, revision or note is added.
        let before = snapshot(&c);
        crate::schema::migrate_control(&mut c).unwrap();
        assert_eq!(snapshot(&c), before);
    }

    #[test]
    fn a_release_that_adds_lists_adopts_the_users_lists_of_their_urls() {
        // A database of the release before 2026-11-07: those six entries unknown, and the user's
        // own lists of their URLs (with content), as the user added them on the PC.
        const ADDED: [&str; 6] = [
            "firehol-level1",
            "abusech-feodo",
            "et-compromised",
            "cins-army",
            "blocklist-de-all",
            "ipsum-level3",
        ];
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::schema::migrate_control(&mut c).unwrap();
        let content = IpRangeSet::from_networks(["203.0.112.0/24".parse().unwrap()]);
        let mut mine = Vec::new();
        for key in ADDED {
            let b = builtin(key).unwrap();
            let id: String = c
                .query_row(
                    "SELECT blocklist_id FROM builtin_blocklists WHERE key = ?1",
                    params![key],
                    |r| r.get(0),
                )
                .unwrap();
            c.execute(
                "DELETE FROM builtin_blocklists WHERE key = ?1",
                params![key],
            )
            .unwrap();
            c.execute(
                "DELETE FROM entity_heads WHERE kind = 'blocklist' AND id = ?1",
                params![id],
            )
            .unwrap();
            let list = entities::insert_in(
                &c,
                Blocklist {
                    id: BlocklistId::new(),
                    meta: meta(),
                    name: format!("使用者的 {key}"),
                    source: BlocklistSource::Url {
                        url: b.url.into(),
                        refresh_hours: Some(48),
                    },
                    stats: BlocklistStats {
                        entries: 1,
                        ..BlocklistStats::default()
                    },
                    content_sha256: content.digest(),
                    content_updated_at: Timestamp::now(),
                    invalid_lines: Vec::new(),
                    builtin: None,
                    enabled: true,
                },
            )
            .unwrap();
            put_content(&c, &list, 1, &content).unwrap();
            mine.push((key, list));
        }

        // The next start: each became that built-in list (no second copy), keeping its name,
        // interval and content.
        crate::schema::migrate_control(&mut c).unwrap();
        let lists: Vec<Blocklist> = entities::list(&c).unwrap();
        assert_eq!(lists.len(), BUILTIN_BLOCKLISTS.len());
        for (key, list) in mine {
            let adopted: Blocklist = head(&c, &list.id);
            assert_eq!(adopted.builtin.as_deref(), Some(key));
            assert_eq!(adopted.name, list.name, "{key}");
            assert_eq!(adopted.source, list.source, "{key}");
            assert_eq!(adopted.content_sha256, content.digest(), "{key}");
            assert_eq!(adopted.meta.revision, 2, "{key}");
            assert!(!adopted.awaiting_content(), "{key}");
        }
    }

    #[test]
    fn a_new_database_gets_the_builtin_lists_and_keeps_a_deleted_one_deleted() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::schema::migrate_control(&mut c).unwrap();
        let lists: Vec<Blocklist> = entities::list(&c).unwrap();
        assert_eq!(lists.len(), BUILTIN_BLOCKLISTS.len());
        assert!(lists.iter().all(|l| l.awaiting_content() && l.enabled));
        let before = snapshot(&c);
        crate::schema::migrate_control(&mut c).unwrap();
        assert_eq!(snapshot(&c), before, "idempotent");

        // A built-in list downloads from its catalogue entry's URL: one stored with another (as a
        // release that moves a source finds it) moves on the next start; its interval stays.
        let drifted = lists.last().unwrap().clone();
        let key = drifted.builtin.clone().unwrap();
        let drifted = entities::update_in(
            &c,
            Blocklist {
                source: BlocklistSource::Url {
                    url: "https://lists.example.net/old.txt".into(),
                    refresh_hours: Some(48),
                },
                ..drifted
            },
            1,
        )
        .unwrap();
        crate::schema::migrate_control(&mut c).unwrap();
        let moved: Blocklist = head(&c, &drifted.id);
        assert_eq!(
            moved.source,
            BlocklistSource::Url {
                url: builtin(&key).unwrap().url.into(),
                refresh_hours: Some(48),
            }
        );
        assert_eq!(moved.meta.revision, 3);

        // The user deletes one (the store's delete marks it), and a later start leaves it out.
        let gone = &lists[0];
        c.execute(
            "UPDATE builtin_blocklists SET blocklist_id = NULL, deleted_at = 'x' WHERE blocklist_id = ?1",
            params![gone.id.to_string()],
        )
        .unwrap();
        c.execute(
            "DELETE FROM entity_heads WHERE kind = 'blocklist' AND id = ?1",
            params![gone.id.to_string()],
        )
        .unwrap();
        crate::schema::migrate_control(&mut c).unwrap();
        let after: Vec<Blocklist> = entities::list(&c).unwrap();
        assert_eq!(after.len(), BUILTIN_BLOCKLISTS.len() - 1);
        assert!(after.iter().all(|l| l.builtin != gone.builtin));
        // A row is either a list or a deletion, never both or neither.
        assert!(
            c.execute(
                "UPDATE builtin_blocklists SET deleted_at = NULL WHERE blocklist_id IS NULL",
                [],
            )
            .is_err()
        );
    }
}
