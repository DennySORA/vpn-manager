//! `vpnctl status`: the service and every connection at a glance.

use vpn_domain::{InstanceView, MetricsRecording, MetricsRecordingState, SystemStatus};

use super::{CmdResult, Ctx, Exit, instances};
use crate::output::{instance_state, recovery_lines, short, table};

/// The ports of an Instance's Gateways, enabled ones only.
pub fn ports(v: &InstanceView) -> String {
    let ports: Vec<String> = v
        .gateways
        .iter()
        .filter(|g| g.enabled)
        .map(|g| g.port.to_string())
        .collect();
    if ports.is_empty() {
        "—".into()
    } else {
        ports.join(", ")
    }
}

pub fn instance_rows(list: &[InstanceView]) -> Vec<Vec<String>> {
    list.iter()
        .map(|v| {
            vec![
                v.spec.name.clone(),
                instance_state(v),
                ports(v),
                v.profile
                    .as_ref()
                    .map_or_else(|| "—".into(), |p| p.name.clone()),
                short(&v.spec.id),
            ]
        })
        .collect()
}

pub const INSTANCE_HEADERS: [&str; 5] = ["名稱", "狀態", "代理埠", "WireGuard 設定", "ID"];

/// The metrics recording, when it is not as usual: writes failing, or the oldest data overwritten
/// on a low or full disk.
fn recording_line(r: &MetricsRecording) -> Option<String> {
    match r.state {
        MetricsRecordingState::Failing => Some(format!(
            "數據統計：無法寫入（{}），樣本暫存在佇列，寫入恢復後自動繼續",
            r.error.as_ref().map_or("原因未知", |t| t.zh_tw.as_str())
        )),
        MetricsRecordingState::Overwriting if r.overwritten_rows > 0 || r.lost_samples > 0 => {
            Some(format!(
                "數據統計：{}，已覆蓋最舊的 {} 筆紀錄{}（新的數據照常記錄）",
                if r.free_bytes == Some(0) {
                    "磁碟已滿"
                } else {
                    "磁碟空間不足"
                },
                r.overwritten_rows,
                if r.lost_samples > 0 {
                    format!("，{} 筆樣本沒有保存", r.lost_samples)
                } else {
                    String::new()
                }
            ))
        }
        _ => None,
    }
}

pub async fn run(ctx: &Ctx) -> CmdResult {
    let system: SystemStatus = ctx.client.get("/v1/system/status").await?;
    let list = instances(ctx).await?;
    if ctx.out.json {
        ctx.out
            .json(&serde_json::json!({ "system": system, "instances": list }));
        return Ok(Exit::Ok);
    }
    let out = &ctx.out;
    out.line(format!(
        "VPN Manager {}（build {}）",
        system.version, system.build_id
    ));
    out.line(format!(
        "manager：{}　管理位址：{}:{}",
        if system.manager_connected {
            "已連線"
        } else {
            "未連線"
        },
        system.controller_listen,
        system.controller_port
    ));
    if !system.controller_allow_clients.is_empty() {
        out.line(format!(
            "允許連入管理介面的網段：{}（其中任何裝置都能操作 VPN Manager）",
            system.controller_allow_clients.join("、")
        ));
    }
    if let Some(dir) = &system.data_dir {
        out.line(format!("資料目錄：{dir}"));
    }
    out.line(format!(
        "連線：{} 條執行中，共 {} 條",
        system.instances_running, system.instances_total
    ));
    if let Some(line) = system
        .store
        .metrics_recording
        .as_ref()
        .and_then(recording_line)
    {
        out.line(line);
    }
    if system.clock_synchronized == Some(false) {
        out.line("主機時間沒有同步（沒有 NTP 等時間同步服務，或還沒同步上）");
    }
    if !list.is_empty() {
        out.line("");
        out.line(table(&INSTANCE_HEADERS, &instance_rows(&list)));
    }
    let held = recovery_lines(&list);
    if !held.is_empty() {
        out.line("");
        for l in held {
            out.line(l);
        }
    }
    Ok(if system.manager_connected {
        Exit::Ok
    } else {
        Exit::Failed
    })
}
