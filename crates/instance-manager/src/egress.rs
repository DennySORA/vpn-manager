//! The Provider egress as the manager answers for it (architecture §7).
//!
//! It covers the binding, the open
//! grant, the runs of the direct exception — and, while the selected egress does not work, whether
//! it needs recovery and whether a manual rebootstrap may be opened. Every decision about direct
//! access (opening, claiming a run's connection, the seal, ending a run) is taken under the
//! bootstrap's lock, so two requests cannot each pass a check alone.
//!
//! A rebootstrap is allowed only when all of these hold (anything else is not a reason to use the
//! raw network): the selected egress is unusable for good — its key is not in the vault, or its
//! peer never answered a handshake over several consecutive attempts —, it was not stopped by the
//! user, its tunnel (not an exit checker or a provider) is what fails, no other connection here is
//! ready, no other valid profile here could be started instead, and no run is active.

use std::collections::HashSet;

use vpn_domain::validation::check_profile;
use vpn_domain::{
    ApiError, BootstrapKind, BootstrapRun, BootstrapStage, DesiredState, EgressMode,
    EgressRecovery, ErrorCode, GatewaySpec, InstanceId, InstanceSpec, InstanceStatus, OperationId,
    Phase, ProfileId, ProviderEgress, RuntimeProfile, SecretRef, Text, Timestamp, tr,
};
use vpn_ipc::control::ChildClaimWire;
use vpn_store::{BootstrapRow, ChildClaim};

use crate::Manager;
use crate::bootstrap::{ActiveGrant, PROMOTE_WAIT};
use crate::resolve::KEY_MISSING;

/// Consecutive start attempts whose peer never answered before an endpoint counts as failed for
/// good (a passing outage of a tunnel that was up does not count).
pub const UNREACHABLE_REQUIRED: u32 = 3;

/// Fault codes of a key that is not usable (see `resolve`).
const KEY_FAULTS: &[&str] = &[KEY_MISSING, "BAD_KEY"];

/// The egress as answered to the controller.
#[derive(Debug, Clone)]
pub struct EgressView {
    pub egress: ProviderEgress,
    pub grant: Option<ActiveGrant>,
    /// The active run, else the latest.
    pub run: Option<BootstrapRun>,
    /// Set while the selected egress does not work.
    pub recovery: Option<EgressRecovery>,
}

/// What the assessment looks at.
pub(crate) struct Facts<'a> {
    pub egress: &'a ProviderEgress,
    pub active_run: Option<&'a BootstrapRow>,
    pub instances: &'a [InstanceSpec],
    pub statuses: &'a [InstanceStatus],
    pub profiles: &'a [RuntimeProfile],
    /// Secrets that exist in the vault.
    pub secrets: &'a HashSet<SecretRef>,
}

fn verdict(required: bool, eligible: bool, code: &str, reason: Text) -> EgressRecovery {
    EgressRecovery {
        required,
        rebootstrap_eligible: eligible,
        reason_code: code.into(),
        reason,
    }
}

/// The words of the last fault, or that it is not known.
fn fault_text(fault: Option<&vpn_domain::Fault>) -> Text {
    fault.map_or_else(
        || tr!("unknown reason", "原因未知", "原因不明"),
        |f| f.message.clone(),
    )
}

/// Unusable for good: its key is not usable, or its peer never answers.
fn failing_for_good(s: &InstanceStatus) -> Option<&'static str> {
    let fault = s.recovery.last_fault.as_ref().map(|f| f.code.as_str());
    if s.phase == Phase::Failed && fault.is_some_and(|c| KEY_FAULTS.contains(&c)) {
        return Some("KEY_MISSING");
    }
    if !matches!(s.phase, Phase::Ready | Phase::Degraded)
        && s.recovery.unreachable_attempts >= UNREACHABLE_REQUIRED
    {
        return Some("ENDPOINTS_FAILED");
    }
    None
}

fn profile_usable(p: &RuntimeProfile, secrets: &HashSet<SecretRef>) -> bool {
    !check_profile(p).has_errors()
        && secrets.contains(&p.interface.private_key)
        && p.peer.preshared_key.is_none_or(|k| secrets.contains(&k))
}

/// The deciding fact about the selected egress: whether it needs recovery, and whether a manual
/// rebootstrap may be opened (with the reason either way).
pub(crate) fn assess(f: &Facts<'_>) -> EgressRecovery {
    if f.egress.desired_mode == EgressMode::Disabled {
        return verdict(
            false,
            false,
            "EGRESS_DISABLED",
            tr!(
                "The Provider egress is turned off; turn it on first",
                "Provider 出口已停用；請先啟用它",
                "Provider 出口は無効になっています。先に有効にしてください"
            ),
        );
    }
    let Some(selected) = f.egress.selected_instance_id else {
        return verdict(
            false,
            false,
            "NO_EGRESS_SELECTED",
            if f.egress.bootstrap_consumed {
                tr!(
                    "No Provider egress connection is selected yet: select a connection, or import a WireGuard profile, create a connection from it and select that one",
                    "還沒有選擇 Provider 出口連線：請選擇一條連線，或匯入 WireGuard 設定建立連線後選為出口",
                    "Provider 出口の接続がまだ選択されていません。接続を選択するか、WireGuard 設定をインポートして接続を作成し、それを出口に選択してください"
                )
            } else {
                tr!(
                    "There is no Provider egress yet: select a connection, or use the first direct connection",
                    "還沒有 Provider 出口：請選擇一條連線，或使用首次直連",
                    "Provider 出口がまだありません。接続を選択するか、初回の直接接続を使ってください"
                )
            },
        );
    };
    let spec = f.instances.iter().find(|s| s.id == selected);
    let name = spec.map_or_else(unknown_name, |s| Text::verbatim(&s.name));
    let Some(status) = f.statuses.iter().find(|s| s.instance_id == selected) else {
        return verdict(
            false,
            false,
            "EGRESS_UNKNOWN",
            tr!(
                "Could not get the state of the egress connection",
                "無法取得出口連線的狀態",
                "出口の接続の状態を取得できません"
            ),
        );
    };
    assess_selected(f, selected, spec, name, status)
}

/// [`assess`] once the selected egress and its status are known: what holds it, or how it
/// fails.
fn assess_selected(
    f: &Facts<'_>,
    selected: InstanceId,
    spec: Option<&InstanceSpec>,
    name: Text,
    status: &InstanceStatus,
) -> EgressRecovery {
    if status.phase == Phase::RecoveryRequired {
        // Waiting for the user's decision (an unconfirmed stop, ownership that cannot be
        // proven): a local decision, never a reason for the raw network. Decided before the
        // manual stop below: the actor reports a held stop in the intent as stopped by hand, but
        // this one is not ended by a Start (an emergency refuses Start until it is cleared); its
        // fault says how to confirm or end it.
        return verdict(
            false,
            false,
            "EGRESS_NEEDS_DECISION",
            tr!(
                "The egress connection “{name}” needs a decision on the Connections page first ({why}); once that is done it recovers, without a direct connection",
                "出口連線「{name}」需要先在連線頁確認處理（{why}）；處理後即可恢復，不需要直連",
                "出口の接続「{name}」は、先に接続ページで対応を決める必要があります（{why}）。対応すれば直接接続なしで復旧します";
                name = name,
                why = fault_text(status.recovery.last_fault.as_ref())
            ),
        );
    }
    let intent = &status.intent;
    if intent.emergency_latched || intent.manual_stop || intent.desired == DesiredState::Stopped {
        return verdict(
            false,
            false,
            "EGRESS_STOPPED",
            if intent.emergency_latched {
                // Start is refused until the emergency is cleared.
                tr!(
                    "The egress connection “{name}” is under an emergency stop; release the emergency stop and start it to recover, without a direct connection",
                    "出口連線「{name}」已急停；解除急停並啟動它即可恢復，不需要直連",
                    "出口の接続「{name}」は緊急停止中です。緊急停止を解除して開始すれば、直接接続なしで復旧します";
                    name = name
                )
            } else {
                tr!(
                    "The egress connection “{name}” was stopped by hand; start it to recover, without a direct connection",
                    "出口連線「{name}」是人工停止的；啟動它即可恢復，不需要直連",
                    "出口の接続「{name}」は手動で停止されています。開始すれば、直接接続なしで復旧します";
                    name = name
                )
            },
        );
    }
    if matches!(status.phase, Phase::Ready | Phase::Degraded) {
        return verdict(
            false,
            false,
            "EGRESS_USABLE",
            tr!(
                "The egress connection “{name}” works; a failed exit check or provider request needs no direct connection, try again later",
                "出口連線「{name}」可以使用；出口檢查或供應商請求失敗不需要直連，請稍後再試",
                "出口の接続「{name}」は使用できます。出口チェックやプロバイダーへのリクエストが失敗しても直接接続は不要です。しばらくしてからもう一度お試しください";
                name = name
            ),
        );
    }
    let Some(code) = failing_for_good(status) else {
        let fault = status.recovery.last_fault.as_ref();
        return if status.phase == Phase::Failed {
            verdict(
                false,
                false,
                "EGRESS_CONFIG",
                tr!(
                    "The egress connection “{name}” needs its settings fixed before it can connect ({why}); once they are fixed it recovers, without a direct connection",
                    "出口連線「{name}」需要修正設定才能連線（{why}）；修正後即可恢復，不需要直連",
                    "出口の接続「{name}」は、接続するには設定の修正が必要です（{why}）。修正すれば直接接続なしで復旧します";
                    name = name,
                    why = fault_text(fault)
                ),
            )
        } else {
            verdict(
                false,
                false,
                "EGRESS_RECOVERING",
                tr!(
                    "The egress connection “{name}” is recovering by itself; a short disconnection needs no direct connection (an endpoint counts as failed only after {UNREACHABLE_REQUIRED} unanswered handshakes in a row)",
                    "出口連線「{name}」正在自動恢復；暫時斷線不需要直連（連續 {UNREACHABLE_REQUIRED} 次握手沒有回應才算端點失效）",
                    "出口の接続「{name}」は自動で復旧中です。一時的な切断では直接接続は不要です（ハンドシェイクに {UNREACHABLE_REQUIRED} 回続けて応答がない場合にだけ、エンドポイントの失効とみなします）";
                    name = name
                ),
            )
        };
    };
    assess_failing(f, selected, spec, &name, status, code)
}

/// The name shown for a connection that is not stored.
fn unknown_name() -> Text {
    tr!("(unknown name)", "（名稱未知）", "（名前不明）")
}

/// [`assess`] once the selected egress fails for good (`code`): whether another local way out
/// exists, or a manual rebootstrap may be opened.
fn assess_failing(
    f: &Facts<'_>,
    selected: InstanceId,
    spec: Option<&InstanceSpec>,
    name: &Text,
    status: &InstanceStatus,
    code: &'static str,
) -> EgressRecovery {
    let why = if code == "KEY_MISSING" {
        tr!(
            "The WireGuard key of the egress connection “{name}” is not on this computer or cannot be used, so it cannot recover by itself",
            "出口連線「{name}」的 WireGuard 金鑰不在這台電腦或無法使用，無法自行恢復",
            "出口の接続「{name}」の WireGuard 鍵がこのコンピューターにないか使用できないため、自動では復旧できません";
            name = name.clone()
        )
    } else {
        let attempts = status.recovery.unreachable_attempts;
        tr!(
            "The server of the egress connection “{name}” did not answer {attempts} handshakes in a row (its endpoint failed, or the device key was revoked), so it cannot recover by itself",
            "出口連線「{name}」的伺服器連續 {attempts} 次沒有回應握手（端點失效，或裝置金鑰已被撤銷），無法自行恢復",
            "出口の接続「{name}」のサーバーがハンドシェイクに {attempts} 回続けて応答していません（エンドポイントの失効か、デバイスの鍵の取り消し）。自動では復旧できません";
            name = name.clone()
        )
    };
    // Another way out that does not use the raw network: a connection that works, or a valid
    // profile that could be started (neither the failing one nor one that fails the same way).
    for other in f.statuses {
        if other.instance_id != selected && other.phase == Phase::Ready {
            let n = f
                .instances
                .iter()
                .find(|s| s.id == other.instance_id)
                .map_or_else(unknown_name, |s| Text::verbatim(&s.name));
            return verdict(
                true,
                false,
                "LOCAL_EGRESS_AVAILABLE",
                tr!(
                    "{why}. The connection “{n}” works: select it as the egress; no direct connection is needed",
                    "{why}。連線「{n}」可以使用：請把它選為出口，不需要直連",
                    "{why}。接続「{n}」は使用できます。これを出口に選択してください。直接接続は不要です";
                    why = why,
                    n = n
                ),
            );
        }
    }
    let selected_profile = spec.and_then(|s| f.profiles.iter().find(|p| p.id == s.profile_id));
    let failing: HashSet<ProfileId> = f
        .statuses
        .iter()
        .filter(|s| failing_for_good(s).is_some())
        .filter_map(|s| f.instances.iter().find(|i| i.id == s.instance_id))
        .map(|i| i.profile_id)
        .collect();
    let same_failing_config = |p: &RuntimeProfile| {
        selected_profile.is_some_and(|sel| {
            sel.interface.public_key == p.interface.public_key
                && sel.peer.public_key == p.peer.public_key
                && sel.peer.endpoint == p.peer.endpoint
        })
    };
    if let Some(p) = f.profiles.iter().find(|p| {
        Some(p.id) != selected_profile.map(|s| s.id)
            && !failing.contains(&p.id)
            && !same_failing_config(p)
            && profile_usable(p, f.secrets)
    }) {
        return verdict(
            true,
            false,
            "LOCAL_PROFILE_AVAILABLE",
            tr!(
                "{why}. This computer still has a usable WireGuard profile, “{profile}”: create (or start) a connection with it and select it as the egress; no direct connection is needed",
                "{why}。這台電腦還有可用的 WireGuard 設定「{profile}」：請用它建立（或啟動）連線並選為出口，不需要直連",
                "{why}。このコンピューターには使用できる WireGuard 設定「{profile}」がまだあります。これで接続を作成（または開始）して出口に選択してください。直接接続は不要です";
                why = why,
                profile = p.name.as_str()
            ),
        );
    }
    if f.active_run.is_some() {
        return verdict(
            true,
            false,
            "BOOTSTRAP_ACTIVE",
            tr!(
                "{why}. A direct connection is already in progress",
                "{why}。已有進行中的直連",
                "{why}。直接接続がすでに進行中です";
                why = why
            ),
        );
    }
    verdict(
        true,
        true,
        code,
        tr!(
            "{why}; the egress can be rebuilt over this computer's current network (a direct reconnection, 10 minutes at most)",
            "{why}；可以用這台電腦目前的網路重新建立出口（重新直連，最多 10 分鐘）",
            "{why}。このコンピューターの現在のネットワークで出口を作り直せます（再度の直接接続、最大 10 分）";
            why = why
        ),
    )
}

/// Whether the assessment is shown on the egress status: only while the selected egress does not
/// work.
fn shown(r: EgressRecovery) -> Option<EgressRecovery> {
    match r.reason_code.as_str() {
        "EGRESS_DISABLED" | "NO_EGRESS_SELECTED" | "EGRESS_USABLE" => None,
        _ => Some(r),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "a `Result::map_err` adapter: it takes the error by value"
)]
fn api(e: vpn_store::StoreError) -> ApiError {
    e.to_api()
}

impl Manager {
    async fn assessment(
        &self,
    ) -> Result<(ProviderEgress, Option<BootstrapRow>, EgressRecovery), ApiError> {
        let store = &self.ctx.store;
        let egress = store.provider_egress().await.map_err(api)?;
        let latest = store.latest_bootstrap().await.map_err(api)?;
        let instances: Vec<InstanceSpec> = store.list().await.map_err(api)?;
        // Only the selected egress decides while it works (or is off, or none is chosen): the
        // other connections and profiles are looked at only when it does not.
        let selected = match egress.selected_instance_id {
            Some(id) if egress.desired_mode == EgressMode::ViaInstance => {
                self.status(id).await.ok()
            }
            _ => None,
        };
        let working = egress.desired_mode == EgressMode::Disabled
            || egress.selected_instance_id.is_none()
            || selected.as_ref().is_some_and(|s| {
                matches!(s.phase, Phase::Ready | Phase::Degraded)
                    || s.intent.manual_stop
                    || s.intent.desired == DesiredState::Stopped
            });
        let (profiles, secrets, statuses) = if working {
            (Vec::new(), HashSet::new(), selected.into_iter().collect())
        } else {
            let profiles: Vec<RuntimeProfile> = store.list().await.map_err(api)?;
            let secrets: HashSet<SecretRef> = store
                .secrets()
                .await
                .map_err(api)?
                .into_iter()
                .map(|s| s.secret_ref)
                .collect();
            (profiles, secrets, self.statuses().await)
        };
        let active = latest.as_ref().filter(|r| r.stage.is_active());
        let recovery = assess(&Facts {
            egress: &egress,
            active_run: active,
            instances: &instances,
            statuses: &statuses,
            profiles: &profiles,
            secrets: &secrets,
        });
        Ok((egress, latest, recovery))
    }

    /// The egress as stored, the open grant, the active (else latest) run, and whether the
    /// selected egress needs recovery.
    ///
    /// # Errors
    ///
    /// A Store error reading the binding, the runs, the Instances, the profiles or the secrets.
    pub async fn provider_egress(&self) -> Result<EgressView, ApiError> {
        let (egress, latest, recovery) = self.assessment().await?;
        let (grant, latest) = self.backed_grant(latest).await;
        Ok(EgressView {
            grant,
            egress,
            run: latest.map(|r| r.view()),
            recovery: shown(recovery),
        })
    }

    /// [`Self::provider_egress`] without the recovery assessment: the binding, the grant and the
    /// run (what a route is made of; read several times per provider request).
    ///
    /// # Errors
    ///
    /// A Store error reading the binding or the latest run.
    pub async fn provider_binding(&self) -> Result<EgressView, ApiError> {
        let store = &self.ctx.store;
        let egress = store.provider_egress().await.map_err(api)?;
        let latest = store.latest_bootstrap().await.map_err(api)?;
        let (grant, latest) = self.backed_grant(latest).await;
        Ok(EgressView {
            grant,
            egress,
            run: latest.map(|r| r.view()),
            recovery: None,
        })
    }

    /// The open grant, only for the active run on record, with the run to show (`latest`, or the
    /// grant's own run). One the Store no longer backs is closed here and never reported (never
    /// a direct route without its record). `latest` may have been read before the grant opened —
    /// its row is committed before the grant is filled in here, and reads take no decision lock
    /// — so only the grant's own run, read after the grant was seen, can close it.
    async fn backed_grant(
        &self,
        latest: Option<BootstrapRow>,
    ) -> (Option<ActiveGrant>, Option<BootstrapRow>) {
        let Some(grant) = self.bootstrap().active() else {
            return (None, latest);
        };
        let holds =
            |r: &BootstrapRow| r.id == grant.run && r.stage.is_active() && r.grant_id.is_some();
        if latest.as_ref().is_some_and(holds) {
            return (Some(grant), latest);
        }
        match self.ctx.store.bootstrap_run(grant.run.clone()).await {
            Ok(Some(own)) if holds(&own) => return (Some(grant), Some(own)),
            Ok(_) => {}
            Err(e) => {
                // Not known now: not reported (no direct route on a guess), and not closed.
                tracing::warn!(error = %e, "provider bootstrap grant not reported: its record could not be read");
                return (None, latest);
            }
        }
        if self.bootstrap().close_grant(&grant) {
            tracing::warn!("provider bootstrap grant without its record closed");
        }
        (None, latest)
    }

    /// Open a manual rebootstrap if — checked now, under the lock — it is allowed; otherwise
    /// `REBOOTSTRAP_NOT_ELIGIBLE` with the reason.
    ///
    /// # Errors
    ///
    /// `RevisionConflict` when the binding changed since `expected_revision`,
    /// `RebootstrapNotEligible` with the reason when it is not allowed, an error opening the grant,
    /// or a Store error.
    pub async fn rebootstrap(
        &self,
        expected_revision: u64,
        operation: Option<OperationId>,
    ) -> Result<EgressView, ApiError> {
        {
            let _d = self.bootstrap().decide().await;
            let (egress, _, recovery) = self.assessment().await?;
            if egress.revision != expected_revision {
                return Err(vpn_store::StoreError::RevisionConflict {
                    expected: expected_revision,
                    current: egress.revision,
                }
                .to_api());
            }
            if !recovery.rebootstrap_eligible {
                return Err(ApiError::new(
                    ErrorCode::RebootstrapNotEligible,
                    tr!(
                        "A direct reconnection is not possible: {why}",
                        "不能重新直連：{why}",
                        "再度の直接接続はできません：{why}";
                        why = recovery.reason
                    ),
                ));
            }
            self.bootstrap()
                .open_rebootstrap(expected_revision, operation)
                .await?;
        }
        tracing::warn!(
            "manual provider rebootstrap opened: provider requests leave directly for ten minutes"
        );
        self.provider_egress().await
    }

    /// Cancel the active rebootstrap: its grant closes now and its connection (if built) is not
    /// promoted. The latch stays set.
    ///
    /// # Errors
    ///
    /// `InvalidState` without an active rebootstrap, `BootstrapInProgress` once it is sealing,
    /// or a Store error.
    pub async fn cancel_rebootstrap(&self) -> Result<EgressView, ApiError> {
        {
            let _d = self.bootstrap().decide().await;
            let run = self
                .ctx
                .store
                .latest_bootstrap()
                .await
                .map_err(api)?
                .filter(|r| r.stage.is_active() && r.kind == BootstrapKind::Rebootstrap)
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "No direct reconnection is in progress",
                            "沒有進行中的重新直連",
                            "進行中の再度の直接接続はありません"
                        ),
                    )
                })?;
            if run.stage == BootstrapStage::Sealing {
                return Err(ApiError::new(
                    ErrorCode::BootstrapInProgress,
                    tr!(
                        "The new connection is becoming the egress and can no longer be cancelled",
                        "新連線正在成為出口，已無法取消",
                        "新しい接続が出口になる途中のため、キャンセルできません"
                    ),
                ));
            }
            self.bootstrap().close_run(&run.id);
            self.ctx
                .store
                .end_bootstrap(
                    run.id,
                    BootstrapStage::Cancelled,
                    "CANCELLED".into(),
                    tr!(
                        "The direct reconnection was cancelled; a new connection (if any) does not become the egress by itself",
                        "已取消重新直連；新連線（若有）不會自動成為出口",
                        "再度の直接接続をキャンセルしました。新しい接続（あれば）が自動で出口になることはありません"
                    ),
                )
                .await
                .map_err(api)?;
        }
        self.provider_egress().await
    }

    /// Claim the active run's one connection for the connect request `operation`.
    ///
    /// # Errors
    ///
    /// A Store error, or an internal error when a run's existing connection has no Instance.
    pub async fn bootstrap_claim(
        &self,
        operation: OperationId,
    ) -> Result<ChildClaimWire, ApiError> {
        let _d = self.bootstrap().decide().await;
        let store = &self.ctx.store;
        let Some(active) = store
            .latest_bootstrap()
            .await
            .map_err(api)?
            .filter(|r| r.stage.is_active())
        else {
            return Ok(ChildClaimWire::None);
        };
        if active.kind == BootstrapKind::Rebootstrap
            && let Some(sel) = store
                .provider_egress()
                .await
                .map_err(api)?
                .selected_instance_id
            && self
                .status(sel)
                .await
                .is_ok_and(|s| s.phase == Phase::Ready)
        {
            // The egress came back: connections go through it, nothing is built over direct.
            return Ok(ChildClaimWire::None);
        }
        Ok(
            match store.claim_bootstrap_child(operation).await.map_err(api)? {
                ChildClaim::None => ChildClaimWire::None,
                ChildClaim::Reserved(r) => ChildClaimWire::Reserved { run: r.id },
                ChildClaim::Existing(r) => ChildClaimWire::Existing {
                    run: r.id,
                    instance: r.child_instance_id.ok_or_else(ApiError::internal)?,
                    profile: r.child_profile_id,
                },
            },
        )
    }

    /// Create the run's connection in one Store transaction (Instance with intent `running`,
    /// Gateway, the run's record) and let its actor start it. The caller checked policy and port.
    ///
    /// # Errors
    ///
    /// The Store's refusal of the run's connection (no active run, or the run already has one),
    /// or another Store error.
    pub async fn bootstrap_create_child(
        &self,
        run: String,
        operation: OperationId,
        instance: InstanceSpec,
        gateway: Option<GatewaySpec>,
    ) -> Result<(InstanceSpec, Option<GatewaySpec>), ApiError> {
        let _d = self.bootstrap().decide().await;
        let deadline = Timestamp::now().plus(PROMOTE_WAIT);
        let (i, g, _) = self
            .ctx
            .store
            .create_bootstrap_child(run, operation, instance, gateway, deadline)
            .await
            .map_err(api)?;
        // Its intent is `running`: the new actor starts it, no Start needed.
        self.instance_created(i.id);
        Ok((i, g))
    }

    /// The run's connection exists: wait for it anew and start it (a durable Start).
    ///
    /// # Errors
    ///
    /// The Store's refusal to resume the run, an internal error when the run has no connection,
    /// or the errors of [`Manager::start_instance`].
    pub async fn bootstrap_resume(&self, run: String) -> Result<InstanceId, ApiError> {
        let child = {
            let _d = self.bootstrap().decide().await;
            let row = self
                .ctx
                .store
                .resume_bootstrap_child(run, Timestamp::now().plus(PROMOTE_WAIT))
                .await
                .map_err(api)?;
            row.child_instance_id.ok_or_else(ApiError::internal)?
        };
        self.start_instance(child).await?;
        Ok(child)
    }

    /// Seal the run: its connection is ready with `generation` and its exit answered through it.
    /// Intent, then the grant closed here, then the latch and the binding committed together. A
    /// run already sealing (its commit was refused, or this start could not finish it) is
    /// committed whatever `generation` says: its grant is closed again if still held, and direct
    /// access is never reopened.
    ///
    /// # Errors
    ///
    /// `NotFound` without the run, `InvalidState` when `child` is not the run's connection or the
    /// run already ended, `ProviderEgressBlocked` when the connection is not Ready with
    /// `generation`, or an error recording a seal step.
    pub async fn bootstrap_seal(
        &self,
        run: String,
        child: InstanceId,
        generation: u64,
    ) -> Result<EgressView, ApiError> {
        {
            let _d = self.bootstrap().decide().await;
            let row = self
                .ctx
                .store
                .bootstrap_run(run.clone())
                .await
                .map_err(api)?
                .ok_or_else(|| {
                    ApiError::not_found(tr!(
                        "the direct connection record",
                        "直連紀錄",
                        "直接接続の記録"
                    ))
                })?;
            if row.child_instance_id != Some(child) {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "This connection was not created by this direct connection",
                        "這條連線不是這次直連建立的",
                        "この接続はこの直接接続で作成されたものではありません"
                    ),
                ));
            }
            match row.stage {
                BootstrapStage::Sealed => {}
                BootstrapStage::InstanceRequested | BootstrapStage::Sealing => {
                    if row.stage == BootstrapStage::InstanceRequested {
                        let s = self.status(child).await?;
                        let current = s.running.as_ref().map(|r| r.generation);
                        if s.phase != Phase::Ready || current != Some(generation) {
                            return Err(ApiError::new(
                                ErrorCode::ProviderEgressBlocked,
                                tr!(
                                    "The new connection reconnected or is not ready yet; check the egress again before making it the egress",
                                    "新連線已重新連線或尚未就緒；重新檢查出口後再設為出口",
                                    "新しい接続が再接続したか、まだ準備ができていません。出口をもう一度チェックしてから出口に設定してください"
                                ),
                            ));
                        }
                        self.bootstrap().seal_intent(&run, child).await?;
                    }
                    let at = self.bootstrap().seal_revoke(&run);
                    self.bootstrap().seal_commit(&run, at).await?;
                    tracing::info!(instance = %child, "provider egress sealed: direct access closed for good");
                }
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "This direct connection has already ended",
                            "這次直連已經結束",
                            "この直接接続はすでに終了しています"
                        ),
                    ));
                }
            }
        }
        self.provider_egress().await
    }

    /// The run's connection did not become the egress: the run goes on within its open grant, or
    /// ends blocked (its grant, if any, closes with it).
    ///
    /// # Errors
    ///
    /// The Store's refusal (no such active run), or another Store error.
    pub async fn bootstrap_abandon(
        &self,
        run: String,
        reason_code: String,
        reason: Text,
    ) -> Result<EgressView, ApiError> {
        {
            let _d = self.bootstrap().decide().await;
            let row = self
                .ctx
                .store
                .abandon_bootstrap_promotion(run.clone(), reason_code, reason)
                .await
                .map_err(api)?;
            if !row.stage.is_active() {
                self.bootstrap().close_run(&run);
            }
            tracing::warn!(run = %run, reason = ?row.reason, "new connection was not made the provider egress");
        }
        self.provider_egress().await
    }

    /// `DELETE /v1/provider-egress/bootstrap`.
    ///
    /// # Errors
    ///
    /// `InvalidState` when the open grant is a rebootstrap, or a Store error.
    pub async fn end_initial_bootstrap(&self) -> Result<EgressView, ApiError> {
        self.bootstrap().end_initial().await?;
        self.provider_egress().await
    }

    /// The user changed the binding: an active run ended with it in the Store (same transaction);
    /// its grant closes here.
    pub(crate) fn binding_changed(&self, ends_runs: bool) {
        if ends_runs {
            self.bootstrap().revoke();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use vpn_domain::{
        Enforcement, EntityMeta, Fault, Health, InstanceIntent, InstanceLimits, InstancePurpose,
        InterfaceSpec, PeerSpec, Persistence, ProfileSource, ProviderKind, RecoveryStatus,
        SecretId, WgKey,
    };

    fn wg(s: &str) -> WgKey {
        WgKey::from_str(s).unwrap()
    }

    fn profile(name: &str, key: SecretRef, endpoint: &str) -> RuntimeProfile {
        RuntimeProfile {
            id: ProfileId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            name: name.into(),
            provider: ProviderKind::Mullvad,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: key,
                public_key: wg("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="),
                addresses: vec!["10.99.0.2/32".parse().unwrap()],
                dns: vec!["10.64.0.1".parse().unwrap()],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: wg("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
                preshared_key: None,
                endpoint: endpoint.parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        }
    }

    fn instance(name: &str, profile: &RuntimeProfile) -> InstanceSpec {
        InstanceSpec {
            id: InstanceId::new(),
            meta: profile.meta.clone(),
            name: name.into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        }
    }

    fn status(
        id: InstanceId,
        phase: Phase,
        fault: Option<&str>,
        unreachable: u32,
    ) -> InstanceStatus {
        InstanceStatus {
            instance_id: id,
            spec_revision: 1,
            intent: InstanceIntent {
                desired: DesiredState::Running,
                manual_stop: false,
                emergency_latched: false,
                intent_revision: 2,
                persistence: Persistence::Durable,
            },
            phase,
            enforcement: Enforcement::Blocked,
            health: Health::Unhealthy,
            running: None,
            tunnel: None,
            dns: None,
            gateways: vec![],
            recovery: RecoveryStatus {
                attempt: unreachable,
                next_retry_at: None,
                last_fault: fault.map(|c| Fault {
                    code: c.into(),
                    message: "測試".into(),
                    at: Timestamp::now(),
                }),
                unreachable_attempts: unreachable,
            },
            observed_at: Timestamp::now(),
            sandbox: None,
        }
    }

    struct World {
        egress: ProviderEgress,
        instances: Vec<InstanceSpec>,
        statuses: Vec<InstanceStatus>,
        profiles: Vec<RuntimeProfile>,
        secrets: HashSet<SecretRef>,
        active: Option<BootstrapRow>,
    }

    impl World {
        /// One egress connection, selected, in `phase` with `fault`.
        fn new(phase: Phase, fault: Option<&str>, unreachable: u32) -> (Self, InstanceId) {
            let key = SecretRef(SecretId::new());
            let p = profile("egress", key, "198.51.100.7:51820");
            let i = instance("東京", &p);
            let id = i.id;
            (
                Self {
                    egress: ProviderEgress {
                        revision: 3,
                        route_revision: 4,
                        desired_mode: EgressMode::ViaInstance,
                        bootstrap_consumed: true,
                        selected_instance_id: Some(id),
                    },
                    statuses: vec![status(id, phase, fault, unreachable)],
                    instances: vec![i],
                    profiles: vec![p],
                    secrets: HashSet::from([key]),
                    active: None,
                },
                id,
            )
        }

        fn assess(&self) -> EgressRecovery {
            assess(&Facts {
                egress: &self.egress,
                active_run: self.active.as_ref(),
                instances: &self.instances,
                statuses: &self.statuses,
                profiles: &self.profiles,
                secrets: &self.secrets,
            })
        }
    }

    #[test]
    fn a_missing_key_or_failed_endpoints_require_recovery_and_allow_a_rebootstrap() {
        let (w, _) = World::new(Phase::Failed, Some(KEY_MISSING), 0);
        let r = w.assess();
        assert!(r.required && r.rebootstrap_eligible, "{r:?}");
        assert_eq!(r.reason_code, "KEY_MISSING");

        let (w, _) = World::new(
            Phase::Reconnecting,
            Some("HANDSHAKE_FAILED"),
            UNREACHABLE_REQUIRED,
        );
        let r = w.assess();
        assert!(r.required && r.rebootstrap_eligible, "{r:?}");
        assert_eq!(r.reason_code, "ENDPOINTS_FAILED");
        // Between attempts (starting again) it is the same verdict.
        let (w, _) = World::new(
            Phase::Connecting,
            Some("HANDSHAKE_FAILED"),
            UNREACHABLE_REQUIRED + 2,
        );
        assert_eq!(w.assess().reason_code, "ENDPOINTS_FAILED");
    }

    #[test]
    fn a_passing_outage_a_manual_stop_or_a_working_tunnel_never_qualify() {
        // Temporarily lost: fewer unanswered attempts than required.
        let (w, _) = World::new(
            Phase::Reconnecting,
            Some("HANDSHAKE_FAILED"),
            UNREACHABLE_REQUIRED - 1,
        );
        let r = w.assess();
        assert!(!r.required && !r.rebootstrap_eligible);
        assert_eq!(r.reason_code, "EGRESS_RECOVERING");
        // Stopped by the user (even with a missing key): start it, no direct access.
        let (mut w, _) = World::new(Phase::Failed, Some(KEY_MISSING), 0);
        w.statuses[0].intent.manual_stop = true;
        w.statuses[0].intent.desired = DesiredState::Stopped;
        let r = w.assess();
        assert!(!r.rebootstrap_eligible);
        assert_eq!(r.reason_code, "EGRESS_STOPPED");
        assert!(
            r.reason.zh_tw.contains("啟動它即可恢復"),
            "{}",
            r.reason.zh_tw
        );
        // An emergency stop on disk: Start is refused until it is cleared, so say so.
        w.statuses[0].intent.emergency_latched = true;
        let r = w.assess();
        assert_eq!(r.reason_code, "EGRESS_STOPPED");
        assert!(r.reason.zh_tw.contains("解除急停"), "{}", r.reason.zh_tw);
        // The tunnel works: a failing exit checker (or provider, or 429) is not the egress.
        let (w, _) = World::new(Phase::Ready, None, 0);
        let r = w.assess();
        assert!(!r.required && !r.rebootstrap_eligible);
        assert_eq!(r.reason_code, "EGRESS_USABLE");
        assert!(shown(r).is_none());
        // A configuration problem is fixed locally.
        let (w, _) = World::new(Phase::Failed, Some("DNS_REQUIRED"), 0);
        assert_eq!(w.assess().reason_code, "EGRESS_CONFIG");
        // Waiting for the user's decision (a stop carried over unconfirmed): decided locally too,
        // even if its endpoint had failed before. The actor reports the held stop in the intent
        // (stopped by hand, the emergency latched, not on disk) — it is still no manual stop
        // that a Start ends: an emergency refuses Start until it is cleared.
        for emergency in [false, true] {
            let (mut w, _) = World::new(Phase::RecoveryRequired, Some("STOP_NOT_CONFIRMED"), 5);
            let i = &mut w.statuses[0].intent;
            i.desired = DesiredState::Stopped;
            i.manual_stop = true;
            i.emergency_latched = emergency;
            i.persistence = Persistence::Pending;
            let r = w.assess();
            assert!(!r.required && !r.rebootstrap_eligible, "{r:?}");
            assert_eq!(r.reason_code, "EGRESS_NEEDS_DECISION", "{r:?}");
            assert!(
                !r.reason.zh_tw.contains("啟動它即可恢復"),
                "{}",
                r.reason.zh_tw
            );
        }
        // Egress off, or nothing selected.
        let (mut w, _) = World::new(Phase::Failed, Some(KEY_MISSING), 0);
        w.egress.desired_mode = EgressMode::Disabled;
        assert_eq!(w.assess().reason_code, "EGRESS_DISABLED");
        w.egress.desired_mode = EgressMode::ViaInstance;
        w.egress.selected_instance_id = None;
        assert_eq!(w.assess().reason_code, "NO_EGRESS_SELECTED");
    }

    #[test]
    fn a_usable_local_profile_or_connection_makes_a_rebootstrap_unnecessary() {
        // Another ready connection.
        let (mut w, _) = World::new(Phase::Failed, Some(KEY_MISSING), 0);
        let key = SecretRef(SecretId::new());
        let p = profile("備用", key, "203.0.113.9:51820");
        let other = instance("大阪", &p);
        w.statuses.push(status(other.id, Phase::Ready, None, 0));
        w.instances.push(other);
        w.profiles.push(p);
        w.secrets.insert(key);
        let r = w.assess();
        assert!(r.required && !r.rebootstrap_eligible);
        assert_eq!(r.reason_code, "LOCAL_EGRESS_AVAILABLE");
        assert!(r.reason.zh_tw.contains("大阪"), "{}", r.reason.zh_tw);
        // Only a stored profile (nothing runs it): still a way out without direct access.
        w.statuses.pop();
        w.instances.pop();
        let r = w.assess();
        assert_eq!(r.reason_code, "LOCAL_PROFILE_AVAILABLE");
        assert!(r.reason.zh_tw.contains("備用"), "{}", r.reason.zh_tw);
        // Without its key it is no way out; a rebootstrap may be opened again.
        w.secrets.remove(&key);
        assert!(w.assess().rebootstrap_eligible);
        // A profile identical to the failing one (same keys, same endpoint) is no way out either.
        let (mut w, _) = World::new(Phase::Reconnecting, Some("HANDSHAKE_FAILED"), 5);
        let mut twin = w.profiles[0].clone();
        twin.id = ProfileId::new();
        twin.name = "複製".into();
        w.profiles.push(twin);
        assert!(w.assess().rebootstrap_eligible);
        // While another run is active, none.
        let (mut w, _) = World::new(Phase::Failed, Some(KEY_MISSING), 0);
        w.active = Some(BootstrapRow {
            id: "r".into(),
            kind: BootstrapKind::Rebootstrap,
            stage: BootstrapStage::GrantActive,
            operation_id: None,
            grant_id: Some("g".into()),
            grant_expires_at: Some(Timestamp::now()),
            child_operation_id: None,
            child_reserved_at: None,
            child_instance_id: None,
            child_profile_id: None,
            promote_deadline: None,
            seal_intent_at: None,
            revoked_at: None,
            reason_code: None,
            reason: None,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        });
        let r = w.assess();
        assert!(!r.rebootstrap_eligible);
        assert_eq!(r.reason_code, "BOOTSTRAP_ACTIVE");
    }
}
