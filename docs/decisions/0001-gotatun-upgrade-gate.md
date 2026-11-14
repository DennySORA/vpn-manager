# 0001 GotaTun 升版關卡

| 項目 | 內容 |
|---|---|
| 狀態 | 採用（2026-11-02）；關卡修訂（2026-11-07：測試只留安全與破壞性邊界，互通改為 dev stack 實機檢查）；2026-11-14 移除「只在分支上升版」，和其他相依一樣在 `main` 上升級 |
| 範圍 | GotaTun（Mullvad 的 userspace WireGuard，MPL-2.0）：資料面加密、握手與底層 UDP |

## 背景

GotaTun 是每條連線的加密核心：每個 Instance worker 內有一個 `Device`，底層 UDP 由 `vpn_tunnel::PinnedUdpFactory` 提供，只跟設定的對端往來。原則是以 crate 釘選、不 vendor 也不 fork；升版要先通過互通、UDP 重建、DNS、轉發、故障與效能關卡；不通過就保留舊鎖檔；執行中不熱換 `Device`。

## 決定

1. **釘選**：workspace `Cargo.toml` 寫精確版本 `gotatun = "=0.10.3"`，`Cargo.lock` 記錄 checksum。不 vendor、不 fork、不打 patch。（vendored 的是 smoltcp，因為兩個 TCP 修正與連線中放大緩衝，與 GotaTun 無關。）
2. **在 `main` 上升版**：和其他相依一樣，有新版就升。改 `Cargo.toml` 的版本 → `cargo update -p gotatun --precise <新版>` → 跑下表的關卡，通過才提交。有一項不通過就先修；修不了就把 `Cargo.toml` 與 `Cargo.lock` 改回舊版、不提交，並在進度紀錄寫明卡在哪裡和之後怎麼升。（2026-11-02 到 2026-11-14 這一點寫的是「只在分支上升版、失敗就丟棄分支」，用來保證「不通過就保留舊鎖檔」；它和這個專案「不開分支、都在 `main`」的做法衝突，2026-11-14 移除。）
3. **不熱換**：`Device` 只在 worker 程序啟動時建立。新版 GotaTun 只能經由新的 build（`vpn-installer upgrade`）進入，新的 worker generation 才會用到；執行中的 worker 不換 `Device`。
4. **回報的版本**：同一筆提交把 `crates/controller/src/diagnostics.rs` 的 `GOTATUN_VERSION` 改成新版本（診斷報告 `components.gotatun` 回報的就是它），並一起提交。提交前比對它與 workspace `Cargo.toml` 的精確釘選（`grep -n GOTATUN_VERSION crates/controller/src/diagnostics.rs` 對 `grep -n '^gotatun' Cargo.toml`；`SMOLTCP_VERSION` 同理）。原本做這個比對的測試不是安全或破壞性邊界，2026-11-07 依測試規則移除。（原本這一步是重新產生第三方授權清單；`scripts/third-party.sh`、`crates/vpnd/third-party.json`、`GET /v1/system/licenses` 與系統頁「第三方授權」已於 2026-11-02 移除。）

## 關卡

全部要通過；指令都在 repo 內，不需要外部帳號。

| 關卡 | 指令 | 證明什麼 |
|---|---|---|
| 靜態檢查 | `cargo fmt --all -- --check`；`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`；`target/tools/bin/cargo-deny --locked check` | 新版在全部 target 下沒有警告、授權與 advisory 通過 |
| 不外洩（真實 WireGuard 加密） | `cargo test -p vpn-tunnel --test loopback_pair` | 兩個真實 tunnel 經 loopback UDP 交換 TCP（IPv4／IPv6），不經固定對端以外的位址送出（`blocked_tx` 為 0）；底層 socket 重開後仍只跟對端往來（`the_underlay_is_opened_again_and_stays_pinned`）；沒有 IPv6 的 tunnel 拒絕 IPv6 目的地、不改走別處 |
| 對端固定 | `cargo test -p vpn-tunnel --lib` | GotaTun 的 endpoint roaming 不能把加密流量導到別處（`pinned_policy_matches_canonical_forms_only`）；gate、來源位址與嚴格隔離的封包過濾 |
| 只經 tunnel | `cargo test -p vpn-instance --test host_sockets --test gateway --test forward --test connector --test dns` | worker 不開主機網路的 socket；代理埠被政策拒絕或 gate 關閉時不改走別處；轉發只送到 lease 的 loopback 目標，封鎖清單與自動封鎖生效；DoT 憑證名稱不符、DoH 轉址是失敗而不是改走別處 |
| 嚴格隔離與停止（Linux） | `cargo test -p vpnd --test strict --test access --test lifecycle`；`cargo test -p vpn-instance-manager --test stops --test recovery` | App 的流量只經 sandbox 的 TUN、存取埠只到 App；兩條同位址的連線互不相通；停止 latch 跨 manager 崩潰保留；恢復只清理證明是自己的資源 |
| 互通（實機，不是測試套件） | dev stack（`scripts/dev-stack.sh --seed`）：經代理埠下載、嚴格隔離連線的 App 經 TUN 與轉發收發、DNS 查詢 | 新版的握手、SOCKS5／HTTP proxy、DNS 與轉發實際可用；結果寫進升版紀錄 |
| 效能 | 沒有工具：主動效能測試在 2026-11-02 移除，手動的單一串流吞吐 `throughput_single_stream_loopback` 在 2026-11-07 隨非邊界測試移除；只剩 dev stack 上「效能統計」的被動觀測（新舊 build 各看一次） | 沒有明顯的退步；退步要在升版紀錄寫明原因，否則不升。要不要恢復正式的效能關卡，由維護者決定 |
| 真實供應商（建議） | dev stack 用一個真實設定檔握手並取回出口 IP | 真實伺服器互通（需要使用者同意使用帳號） |

## 結果紀錄

每次升版在維護者的工作紀錄（`docs/process/README.md`，不隨公開的版本發布）新增一列：舊版與新版、每個關卡的結果（效能關卡寫明比較了什麼、數字多少）、判定。沒有這一列的升版不算完成。
