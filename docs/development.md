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
# 檢查工具裝在 repo 內（target/tools，不進 Git），不裝到全域
cargo install cargo-deny taplo-cli typos-cli --locked --root target/tools
target/tools/bin/cargo-deny --locked fetch              # 安全公告資料庫（之後離線檢查）
(cd web && pnpm install --frozen-lockfile)
(cd scripts && uv sync --frozen)                        # ruff、mypy、shellcheck、shfmt（scripts/uv.lock）
```

- **OSV-Scanner**：從 [官方 release](https://github.com/google/osv-scanner/releases) 下載本機平台的執行檔與 `osv-scanner_SHA256SUMS`，比對雜湊後放進 `target/tools/bin/osv-scanner`。資料庫下載一次：`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=target/tools/osv-db target/tools/bin/osv-scanner scan source --offline --download-offline-databases -L Cargo.lock -L scripts/uv.lock`。
- **Semgrep**（裝在使用者自己的環境）：官方規則集只供內部使用，所以抓到 `target/tools/semgrep-rules/`（不進 Git、不隨任何產物散布）：`p/rust`、`r/rust`、`p/python`、`r/bash`，網址是 `https://semgrep.dev/c/<規則集>`。

## 靜態檢查

每次修改後，跑碰到的 owner 的檢查；warning 一律算失敗。

| Owner | 指令（repo 根目錄，web 在 `web/`） |
|---|---|
| Rust workspace | `cargo fmt --all -- --check`<br>`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`<br>`target/tools/bin/cargo-deny --locked check` |
| Rust，macOS 專屬的程式碼 | 在 Mac 上跑上一列。在 Linux 上只能檢查相依不需要 C 編譯器的 crate（一次性：`rustup target add aarch64-apple-darwin`）：<br>`cargo clippy -p vpn-platform -p vpn-ipc -p vpn-domain -p vpnctl -p vpn-ssh -p vpn-sync -p vpn-performance -p vpn-web-provide --all-targets --all-features --locked --offline --target aarch64-apple-darwin -- -D warnings` |
| scripts | `scripts/check.sh`：ruff format／lint、strict mypy、ShellCheck（全部選項）、shfmt，以及介面語言的檢查 `scripts/text_guard.py`（Rust 產品程式碼裡寫給人看的文字都要有三種語言） |
| 全 repo 的衛生檢查 | `target/tools/bin/typos`（拼字，專案用字在 `_typos.toml`）<br>`target/tools/bin/taplo fmt --check`、`target/tools/bin/taplo check`（TOML，風格在 `.taplo.toml`，不抓 schema）<br>`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=target/tools/osv-db target/tools/bin/osv-scanner scan source --offline -L Cargo.lock -L scripts/uv.lock`<br>`semgrep scan --metrics off --disable-version-check --error --no-rewrite-rule-ids --exclude-rule rust.lang.security.unsafe-usage.unsafe-usage --config target/tools/semgrep-rules/p-rust.yaml --config target/tools/semgrep-rules/r-rust.yaml crates`，以及 `--config …/p-python.yaml --config …/r-bash.yaml scripts`：`unsafe-usage` 只是把每個 `unsafe` 區塊列出來請人看，這件事 Clippy 的 `undocumented_unsafe_blocks`、`multiple_unsafe_ops_per_block` 與 `unsafe_code` 的 `expect` 已經強制（每個 unsafe 操作單獨一塊、寫明 SAFETY）；其他規則的例外寫在那一行的 `nosemgrep` 並附理由 |
| web | `pnpm format:check`、`pnpm lint`（typed ESLint，0 warning；接著 dependency-cruiser 依 `web/.dependency-cruiser.json` 檢查 `src` 的分層、循環引用與沒有被引用的檔案）、`pnpm typecheck`、`pnpm build` |

規則本身在各自的設定檔：`Cargo.toml` 的 `[workspace.lints]`（warnings、`unsafe_code`、rustc 的 `missing_debug_implementations`／`unused_qualifications`／`rust_2018_idioms` 等、Clippy 的 all／pedantic／nursery／cargo 與 `expect_used`、`panic`、`print_stdout`、`string_slice`、`let_underscore_must_use`、`map_err_ignore`、`allow_attributes` 等限制類 lint，以及 Cargo 自己的 lint）、`clippy.toml`、`rustfmt.toml`、`deny.toml`、`scripts/pyproject.toml`、`web/eslint.config.ts`、`web/tsconfig.json`。不放寬既有的規則；需要例外時，在那一處以 `#[expect(…, reason = "…")]`（Rust）或附理由的註解寫明，不用 `#[allow]`。持有秘密（金鑰、密碼、token、帳號）的型別手寫 `Debug`，不印出秘密。

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
