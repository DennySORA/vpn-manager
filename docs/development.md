# 開發與檢查

從原始碼建置、檢查、測試與打包 VPN Manager 的做法。設計與取捨在 [architecture.md](architecture.md)，前端的設計契約在 [frontend-design.md](frontend-design.md)。

## 需要的工具

- **Rust**：rustup；`rust-toolchain.toml` 會自動選用釘選的版本。還要一個 C 編譯器（AWS-LC 與內建的 SQLite 要編 C）。
- **Node 與 pnpm**：Node 的版本在 `web/.nvmrc`（`web/package.json` 的 `engines` 是下限），pnpm 的版本釘在 `web/package.json` 的 `packageManager`。
- **uv 與 python3**：`scripts/check.sh` 以 uv 執行 `scripts/uv.lock` 鎖定的工具（ruff、mypy、shellcheck）；`scripts/package.sh` 以 `python3` 產生授權聲明。
- **磁碟**：跑完全部檢查、測試與打包後，`target/` 約 22 GB。

平台：Linux（x86_64、aarch64）與 macOS（Apple silicon、Intel）。嚴格隔離（sandbox）只在 Linux。

## 第一次

```sh
cargo fetch --locked                                    # 之後的 cargo 指令都帶 --offline
cargo install cargo-deny --locked --root target/tools   # 檢查工具裝在 repo 內，不裝到全域
(cd web && pnpm install --frozen-lockfile)
```

## 靜態檢查

每次修改後，跑碰到的 owner 的檢查；warning 一律算失敗。

| Owner | 指令（repo 根目錄，web 在 `web/`） |
|---|---|
| Rust workspace | `cargo fmt --all -- --check`<br>`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`<br>`target/tools/bin/cargo-deny --locked check` |
| Rust，macOS 專屬的程式碼 | 在 Mac 上跑上一列。在 Linux 上只能檢查相依不需要 C 編譯器的 crate（一次性：`rustup target add aarch64-apple-darwin`）：<br>`cargo clippy -p vpn-platform -p vpn-ipc -p vpn-domain -p vpnctl -p vpn-ssh -p vpn-sync -p vpn-performance -p vpn-web-provide --all-targets --all-features --locked --offline --target aarch64-apple-darwin -- -D warnings` |
| scripts | `scripts/check.sh`：ruff format／lint、`mypy --strict`、shellcheck，以及介面語言的檢查 `scripts/text_guard.py`（Rust 產品程式碼裡寫給人看的文字都要有三種語言） |
| web | `pnpm format:check`、`pnpm lint`（typed ESLint，0 warning；接著 dependency-cruiser 依 `web/.dependency-cruiser.json` 檢查 `src` 的分層、循環引用與沒有被引用的檔案）、`pnpm typecheck`、`pnpm build` |

規則本身在各自的設定檔：`Cargo.toml` 的 `[workspace.lints]`（warnings、`unsafe_code`、Clippy 的 all／pedantic／nursery／cargo、`allow_attributes_without_reason`，以及 Cargo 自己的 lint）、`clippy.toml`、`deny.toml`、`scripts/pyproject.toml`、`web/eslint.config.ts`、`web/tsconfig.json`。不放寬既有的規則；需要例外時，在那一處寫明理由。

## 測試

測試只留安全與破壞性邊界：隔離與不外洩、授權、檔案與連結、資料完整性、秘密、要確認的破壞性操作。改到這些邊界時，跑那個 owner 的測試：

```sh
cargo test -p <crate> --locked            # 例如 vpn-tunnel、vpn-store、vpn-platform
cargo test --workspace --locked --no-fail-fast
(cd web && pnpm test)
```

- 測試會建立 Unix socket：`TMPDIR` 的路徑要短，太長的路徑會讓這些測試失敗。
- 畫面的改動不寫瀏覽器測試，以隔離的瀏覽器截圖檢視。

## 本機開發堆疊

`scripts/dev-stack.sh --seed` 在 loopback 上啟動一整套：WireGuard 對端 `vpn-labpeer`（附測試用的服務）、`vpnd` 的 manager 與 controller，資料放在自己的狀態目錄，不會碰到已安裝的 VPN Manager。介面在 <http://127.0.0.1:28765>；選項見腳本開頭的說明。

## 不外洩的封包證據（Linux）

`scripts/leak-capture-linux.sh --src . --build` 在自己的 network namespace 裡（不需要 root，不改動主機）跑一組情境——正常、worker 被終止、對端消失、DNS 不通、嚴格隔離、沒有 IPv6 tunnel 時的 IPv6——同時在假的實體網卡上擷取封包，確認受保護的流量從不在 tunnel 之外出現。輸出目錄（`--out`）的路徑要短。改到資料面、sandbox 或 DNS 時跑一次。

## 打包與發布

- `scripts/package.sh` 建出這台機器的安裝檔 `dist/vpn-installer-<版本>-<os>-<arch>`，附 `.sha256` 與第三方授權聲明 `.notices.txt`（`vpn-installer licenses` 印出同一份）。
- 推送 `v<版本>` 的 tag 後，`.github/workflows/release.yml` 在四個平台各建一個安裝檔，附到**草稿** release；發布草稿由人決定，`scripts/install.sh` 只看得到已發布的 release。
