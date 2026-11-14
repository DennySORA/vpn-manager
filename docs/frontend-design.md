# 前端設計契約（VPN Manager 工作台）

狀態：**v2.0（2026-11-02）——設計系統改為 Phasyn Studio 的系統**，取代 v1.x 的「Noir Workbench／不用玻璃模糊」方向。整個前端採用它的風格、動態與過渡，操作聚合在物件上，往後的開發也維持同樣的風格與互動水準：**之後所有新增或修改的前端畫面都必須遵守本文件 §3–§8**，不另訂樣式或動畫做法；與本文件不一致的既有畫面依 §10 末的清單逐步改寫。

- 來源：Phasyn Studio（Apache-2.0）的 `index.css`、`components/ui/*`（motion、look、按鈕、欄位、對話框、選單、分頁、表格、狀態…）、`components/common/*`、`components/workbench/*` 與外殼，移植到 `web/src/styles/*`、`web/src/components/ui/*`、`web/src/components/shell/*`；每個移植的檔案開頭有 `Adapted from Phasyn Studio (Apache-2.0)`，授權見 [`web/THIRD_PARTY_NOTICES.md`](../web/THIRD_PARTY_NOTICES.md)。Phasyn 的名稱、標誌、字標、區域圖示、插圖、極光背景圖與類型圖示**不在授權範圍、沒有複製**：VPN Manager 保留自己的名稱與盾牌標誌，背景只用 CSS。
- 實作：React 19＋TypeScript＋Vite＋Tailwind CSS v4＋Radix（`radix-ui`）＋TanStack Query；動態用 Motion（motion.dev），主視覺用 three.js（React Three Fiber），見 §7。只有深色；介面有繁體中文、英文與日文（`web/src/i18n/README.md`），技術識別字保留原文。

## 1. 使用者與產品形態

- 使用者：同一台主機的工程師／進階使用者，在 `127.0.0.1` 管理多條 WireGuard 出口（安裝時可開放給列出的區網網段，沒有登入；見 §10「管理介面開放給區網」）。繁體中文介面，技術識別字保留原文。
- 形態：桌面工作台，主要 1440×900、1280×800，最小 1024 寬；不做手機專版（窄於 1280 時 inspector 改為右側 sheet，窄於 840 時側欄改為抽屜；寬表格在自己的容器內水平捲動）。
- 核心誠實原則：**只顯示觀測到的事實**。未知就說未知；`provider_match=unknown` 不畫綠色；未觀測的連通不顯示「已連線」；停止要收到封閉證據才顯示「已停止」。

## 2. 檢視地圖（路由即狀態）

| 路由 | 檢視 | 組成 |
|---|---|---|
| `/` | 總覽 | 保護狀態摘要（每個 Instance 一行：狀態、出口、即時速率）＋效果區 A（拓撲）＋流量圖＋需要處理的項目 |
| `/instances`、`/instances/:id` | 連線（Instance） | 清單（篩選 `state`、排序 `sort`、批次「重新啟動待套用」）＋右側 inspector，分頁 `?tab=`：概況（結論、即時速率圖、代理埠）／證據（狀態證據、自動恢復）／資源（頻寬與程序上限）／設定；`?do=<動作>` 開該動作的對話框（指令面板） |
| `/profiles`、`/profiles/:id` | WireGuard 設定 | 清單＋inspector；匯入對話框（貼上／選檔 → 預覽 → 建立） |
| `/gateways`、`/gateways/:id` | 代理埠 | 表格（埠、協定、所屬 Instance、狀態、連線數；篩選 `state`、排序 `sort`）＋右側 inspector（即時、使用方式、設定；主要動作「複製代理位址」）；`?do=edit`／`?do=delete` |
| `/forwards`、`/forwards/:id` | 轉發 | 表格（名稱＋協定／tunnel port、目標 App:port、連線、狀態、外部可達）＋右側 inspector（狀態與原因、外部可達證據、目標與 lease、這一代的計數、設定）；`?new=1` 開新增對話框，`&app=` 預選 App；連線由 VPN Manager 裡的 AirVPN 帳號建立時，對話框列出該帳號的連入埠 |
| `/apps`、`/apps/:id` | 受管 App | 表格（名稱＋隔離方式＋執行檔、連線＋代理埠、狀態、程序數、啟停）＋右側 inspector，分頁 `?tab=`：概況（結論、執行事實；strict 時一列 App 沙箱的即時 ↓／↑）／流量（只有 strict：所屬連線的 App 沙箱，含經轉發連入的連線）／程序（程序樹、資源上限）／連接埠（監聽的連接埠、本機存取埠、轉發）／輸出（輸出紀錄）／設定（執行檔核准、設定）；`?new=1` 開新增對話框（strict 時以「本機存取埠」取代代理埠欄位） |
| `/dns` | DNS 設定 | 清單＋編輯器（UDP／TCP／DoT／DoH 伺服器列） |
| `/transport`、`/transport/:id`、`/transport/new?from=` | 傳輸設定 | 清單（「內建」「我的設定」兩組）＋詳細：內建設定唯讀，主要動作「複製成我的設定」；自訂設定是編輯器——固定（TCP 緩衝的起始與上限、TCP 行為與逾時、UDP）或自動（每個往返時間區間選一份固定設定）、健康探測、使用中的連線；儲存後立即套用，不需要重新啟動；`?do=delete` |
| `/security`、`/security/:id` | 安全設定 | 清單＋編輯器，分頁 `?tab=`：概況（名稱、使用中連線的套用狀態）／目的地（私網允許、防火牆允許規則、封鎖埠）／封鎖（IP 封鎖清單選取、自動封鎖）；檢查順序在頁首（?） |
| `/security/blocklists`、`/security/blocklists/:id`、`/security/blocklists/new` | IP 封鎖清單 | 清單＋詳細（概況、內容統計與無效行、使用中的設定與連線的套用版本、設定、更新內容）；新增：上傳／貼上／網址 → 預覽 → 建立 |
| `/security/bans?instance=` | 自動封鎖紀錄 | 適用範圍說明（是否有 port forward）＋表格（來源、連線、原因與封鎖時間、剩餘、解除） |
| `/providers/:id` | 供應商（Mullvad、AIRVPN） | 連線狀態條（路徑／出口 Instance／IP／國家城市／match）＋帳號頁，分頁 `?tab=`：概況（建立的連線、帳號）／連入埠（只有 AirVPN）／裝置／功能檢查；要向供應商讀的在分頁開啟時才讀 |
| `/ssh` | SSH 主機 | 清單＋編輯器、Include 狀態、連線測試 |
| `/ssh-downloads`、`/ssh-downloads/:id` | SSH 下載 | 清單＋右側 inspector，分頁 `?tab=`：進度（結論、進行中的檔案、佇列）／紀錄（「清除傳輸紀錄…」）／日誌（「清除日誌…」）／設定（連線、資料夾、設定、紀錄） |
| `/metrics` | 數據統計（導覽「觀測」） | 範圍（15 分鐘–30 天）、對象（全部連線／一條連線／一個代理埠）、排序與分頁都在 URL；分頁 `?view=`：流量（流量、WireGuard、連線數）／延遲與 DNS（延遲、DNS 查詢、快取命中率）／資源（CPU、記憶體）——這三頁都以範圍摘要與缺口圖例開頭，圖各有表格檢視、同頁共用游標——／各連線（每條連線、代理埠與 App 沙箱的分解表，列的圖表鈕縮小對象並回到流量）／保存（保存與缺口面板） |
| `/performance` | 效能統計 | 即時觀測，分頁 `?view=`（都以產品摘要開頭）：程序（產品程序的 CPU／記憶體、依角色的資源趨勢）／連線（各連線與代理埠的狀態，選一條在下方看趨勢，`?instance=` 而沒有 `view` 時顯示這頁）／線索（瓶頸線索與參考規模，分頁上標出線索數） |
| `/system` | 系統 | 分頁「狀態／能力／診斷／執行環境／恢復／操作紀錄」（`?view=`）：狀態＝健康結論＋五項事實、存取網址、這個安裝、指標設定、金鑰保管庫；能力＝分組的主機能力（寬時兩欄）；診斷＝結論與計數、檢查結果、擁有的資源、資料庫；執行環境＝同一份報告的結論，加上程序、磁碟空間、程式與版本、位置與檔案、指標與 SSH，可下載 JSON；恢復＝遺留資源的檢查與清理；操作紀錄＝最近操作（原本頂欄的抽屜） |

篩選、排序、選取放在 URL query，可重新整理與返回。

## 3. 外殼與版面

```
+--------+-----------------------------------------------------------------------+
| ◆      | 🖧 連線 › 東京出口                       ● 服務正常   ⟲     ↓ 2.1M ↑ 120K   |  44px（底緣一條淡品牌漸層細線）
|  總覽  +-----------------------------------------------------------------------+
| ⌄ 出口 | [圖示磚] 標題（20px）                                       主要動作  |
| ▌連線  | 一行說明                                                              |
|  …     +----------------------------------------------+------------------------+
| › SSH 2| 工具列：搜尋／篩選（分段）／計數 ……… 批次動作 | Inspector（raised）    |
| ⌄ 觀測 | 表格（sticky 標頭、選取列）                  | 物件標頭＋動作列       |
|  …     |                                              | 屬性區段……             |
| ● 服務 |                                              | 固定底部動作列         |
| ⇤ 收合 |                                              |                        |
+--------+----------------------------------------------+------------------------+
 玻璃側欄 232px／圖示軌 64px；窄於 840px 時改為左側抽屜
```

- **外殼**（`components/shell/app-shell.tsx`）：`h-dvh` grid `[auto_minmax(0,1fr)]`、`overflow-clip`；文件本身永遠不捲動，每個面板是自己的 scroll owner（側欄導覽、清單、inspector、對話框內文）。窄於 840px 時側欄是抽屜、主區占滿寬度（頁面內的欄位在頁面階段才改為上下堆疊）；視窗變寬超過 840px 時開著的抽屜自動關閉。
- **側欄**（`sidebar.tsx`）：`material-sidebar` 玻璃；展開 232px、收合為 64px 圖示軌（偏好存在瀏覽器 `vpnm.flag.shell.sidebar.collapsed`，讀寫失敗用預設；窄於 1600px 的視窗預設收合）；窄於 840px 改為左側抽屜（頂欄「開啟導覽」，選了連結就關閉）。頂端 64px 品牌區（VPN Manager 標誌＋光暈＋名稱，收合時只有標誌）；導覽是「總覽」加六組：出口（連線、供應商、WireGuard 設定）、代理與 App（代理埠、受管 App、轉發）、SSH（SSH 主機、SSH 下載）、觀測、政策、主機（`nav.ts` 的 `NAV_GROUPS`，每組有固定的 `id`）。每組的組名是一顆切換鈕（`aria-expanded`、`aria-controls`，Enter／Space；箭頭以 snappy 彈簧轉向），收起時項目以 smooth 彈簧的 `grid-template-rows` 收合、立即 `inert` 並對輔助技術隱藏，組名旁寫收起的項目數；**目前頁面的項目永遠留著**（在收起的組裡也只剩它一項），所以所在的頁面不會被藏起來。收起狀態每組各存一個瀏覽器偏好（`vpnm.flag.sidebar.group.<id>`，讀寫失敗用展開）。圖示軌沒有組名：組與組之間是分隔線，所有項目都顯示（不受收起影響），名稱改為右側提示。組名 24px、導覽項目 36px（全部展開時 1512×982 放得下）；目前項目是 `border-action/25 bg-brand-gradient-soft` 加以共用漸層描邊的圖示，左緣一條 **3px** 品牌漸層標記（`ActiveIndicator edge="left"`）以 snappy 彈簧在項目間滑動。底部：服務狀態卡（點＋文字、版本與開啟的位址）與收合鈕（`aria-expanded`、`aria-controls`）。
- **頂欄**（`topbar.tsx`）：44px，`bg-canvas/70`＋底緣 `bg-brand-gradient opacity-25` 細線。左：目前位置（區段圖示〔品牌青〕＋名稱 › 物件名稱；物件名稱同時是文件標題）；右：即時流量條（`features/traffic/traffic-strip.tsx`，由 `app/router.tsx` 交給外殼，≥840px）、語言選單（`components/shell/language-menu.tsx`，2026-11-11：地球圖示按鈕，展開繁體中文／English／日本語，各以自己的文字寫、目前的打勾；選了記在這個瀏覽器並重新載入頁面，見 [架構 §7d](architecture.md#7d-介面語言)）與服務狀態 chip（連線中時旋轉圖示＋底緣 shimmer 細線，≥1280px 才顯示）。沒有搜尋欄與指令面板（2026-11-06 依設計規範移除 ⌘K 指令面板）；最近操作在「系統 › 操作紀錄」。
- **即時流量條**（2026-11-06）：一顆 chip 樣式的按鈕，分段是所有應該執行的連線最新一秒的下載、上傳（payload，bit/s，系列色箭頭）與 tunnel 內的 TCP 連線＋UDP 流；視窗變窄時依序收起（連線數 < 1280px、整條 < 840px，總覽仍有同樣的速率）；按鈕的無障礙名稱是完整的一句話（也包含收起的分段）。資料只讀事件串流已放進快取的 `live_rates`（`useLiveRatesMap`，沒有自己的輪詢）；只算主機時間 3.5 秒內的樣本（見下一條），沒有執行中的連線或沒有樣本時是「—」並說原因，有連線沒有樣本時合計標明未計入。按下開 popover（`components/ui/popover.tsx`：popover 玻璃、從觸發端 pop-in，Escape 與點外面關閉、焦點回到按鈕）：每條執行中的連線一列（名稱連到 inspector、狀態、↓／↑、TCP／UDP、有 App 沙箱時「其中 App 沙箱」），底部「在連線頁查看」。
- **主機的時間**（2026-11-07）：伺服器的時間戳記（即時樣本的 `at`、`observed_at`、到期、建立時間）一律和主機自己的時間比，不和這台裝置的時鐘比。`GET /v1/system/status` 的 `observed_at` 在回答送出時蓋上，回答到達時得到「主機減瀏覽器」的時差（`lib/server-clock`；側欄每 15 秒輪詢，差不到 250 ms 不更新）；共用的一秒時鐘加上它就是 `useServerNow`，「12 秒前」、倒數、圖的時間窗與即時數字的新鮮度都用它；只有比較瀏覽器自己的時間（例如 react-query 的 `dataUpdatedAt`）才用 `useNow`。一台主機的時鐘慢 30.5 秒（沒有 NTP）時，總覽、即時流量條、流量路徑與 App 概況的流量全是「—」；現在照常顯示，而資料真的停住時（manager 凍結）仍在 3.5 秒後變成「—」。兩邊相差 5 秒以上時，系統 › 執行環境的「時間」用 warning Callout 說差多少、主機是否同步、該做什麼（面板另列主機時間、時差與同步狀態）；主機沒有時間同步時，總覽的需要處理列出「主機時間」（連到執行環境），診斷多一項警告。
- **背景**：固定在最底層的深空底色——`bg-canvas` 上的 `--gradient-space`（頂端藍色、右下淡紫兩個 radial 光暈），只用 CSS、沒有圖片；透過側欄玻璃與面板之間的縫隙被看到，從不放在密集資料後面當裝飾。
- **主要區域**：`main#main-content`（`tabIndex=-1`，跳到主要內容的目標）；服務中斷時頂端常駐全域橫幅。
- **頁面骨架**（`components/shell/page.tsx`）：`Page` › `PageHeader`（36px 品牌淡漸層圖示磚〔預設為導覽區段的圖示〕＋20px 標題 `h1#page-title`＋一行說明＋右側主要動作）› `Toolbar`（搜尋、篩選、計數，批次動作放最後）› `SplitView`（清單 `panel`＋inspector `panel-raised` 340px〔≥1920 為 400px〕；窄於 1280px 時 inspector 是右側 sheet）或 `MasterDetail`（短清單＋寬編輯器）。頁面左右留白 24px，面板間距 16px。 右側詳細面板（≥1280px）可收合成 44px 軌（`data-panel-toggle`，偏好存在 `vpnm.flag.shell.inspector.collapsed`）；選了物件就自動展開；沒有選取時只占 260px。寬度立即改變，只有內容從邊緣滑入。
- **斷點**：`sm` 480、`md` 840（側欄改抽屜）、`lg` 1280（inspector 欄）、`xl` 1440，VPN Manager 另有 `2xl` 1920（寬 inspector）。
- **焦點**：每頁有跳到主要內容的連結；換頁（換到另一個導覽區段）後焦點移到新頁的 `h1`；同一頁選另一個物件（路徑 `/instances/:id` 改變）或只改 query 時焦點不動。

## 4. Token、色彩與材質（token 唯一 owner：`web/src/styles/tokens.css`）

- **唯一 owner**：`tokens.css`（Tailwind v4 `@theme`／`@theme static`／`@utility`）；基底、元件 class、View Transition、減少動態與強制色彩在 `app.css`。元件只用 token 名稱，不寫散落的 hex；新的 utility 寫在 `tokens.css` **並且**登記在 `lib/cn.ts`（tailwind-merge 才不會把它當成別的東西合併掉）。`--color-*: initial` 清空了 Tailwind 預設色盤：不存在的色名不會產生 CSS（邊框會退回 currentcolor），新的色彩 class 要在建置後的 CSS 確認。
- **表面**：canvas `#070b14`（App 底）、rail `#050810`、sunken `#04060c`（輸入、程式碼、表格標頭）、surface `#0b1120`（面板）、raised `#121a2d`（浮起、hover、次要按鈕）、overlay `#172139`、selection `#17284d`（選取列）。線：line-subtle `#162038`、line `#222e4a`、line-strong `#34446c`（裝飾線）、line-control `#6d7ca6`（必要的控制邊界 ≥3:1）。文字：fg `#eef3ff`、fg-secondary `#b5bfd9`、fg-tertiary `#929ec0`、fg-disabled `#5d6889`（只給停用控制）。
- **品牌光**（訊號，不是填色）：brand-cyan `#49cfff` → brand-blue `#3e89ff` → brand-iris `#727dff` → brand-violet `#ab7bff`；brand-soft = 藍 14%。四組漸層：`bg-brand-gradient`（細線、目前標記、進度、指示線；**上面不放白字**）、`bg-brand-gradient-soft`（同色 16%：目前項目、選取的選項、亮起的選單項目）、`bg-action-gradient`（`#2767de → #4d5fe3 → #7a4fd9`：實心主要按鈕、開關的開啟軌道，白字 ≥5.1:1）、`--gradient-space`（深空底色）。前三者與 `.skeleton` 帶一層平常看不到的 shimmer 高光，只有加上 `animate-shimmer` 才會掃過。
- **操作與語意色**：action `#3a78f2`（選取列左線、勾選、指示線）、action-fg `#8fb0ff`（連結、目前項目圖示）、on-accent `#050912`（亮色填色上的字）、focus `#5fd6ff`（焦點框）。語意色只標事實、一律搭配圖示與文字：info `#74c2ff`、entity `#c3a3ff`、file `#6cd8ca`、success `#5bd69a`（只用於**觀測到的**成功）、warning `#ebc07a`、danger `#f48792`、danger-fill `#f7a3ab`（破壞性確認鈕）。成功從不用漸層，漸層從不代表狀態。圖表系列色另有一組（下載 `#1aa0d2`、上傳 `#8f62e2`、延遲 p50／p95／p99 單色相順序色），只用於資料標記。
- **材質**（macOS vibrancy，只在四個地方）：`material-sidebar`（側欄）、`material-popover`（選單、提示、通知、指令面板）、`material-sheet`（對話框、側邊 sheet、導覽抽屜）、`material-hud`（媒體上的控制，保留）；`.overlay-surface` 給圖表 tooltip 之類的小浮層。不支援 `backdrop-filter` 時退回接近不透明的同色；強制色彩時一律 `Canvas`。對話框遮罩 `rgb(2 4 10 / 0.66)`＋6px 模糊；對話框與 sheet 頂端一條品牌漸層細線。規則：畫面上最多三層模糊（側欄＋一個浮層＋一個 HUD）、材質裡不再疊材質、模糊半徑從不做動畫。表格、表單、inspector、程式碼、清單列一律實心。
- **陰影與光邊**：`shadow-edge`（每個面板的內緣頂光）、`shadow-raised`（`panel-raised`，每個 view 最多兩處）、`shadow-popover`、`shadow-window`、`shadow-glow-sm`／`shadow-glow`（主要按鈕 hover／焦點與「進行中」，從不用在資料上；同一時間只有一個目前標記發光）。`border-brand-gradient`（`::after` 1px 漸層光邊，畫在子元素之下）與 `.brand-edge`（畫在滿版內容之上）；強制色彩下改為 `CanvasText` 外框／隱藏。
- **圓角**：sm 5（鍵帽、小計數）、md 8（按鈕、輸入）、lg 12（面板、導覽項目、選單項目）、xl 14（對話框、選單、通知）、2xl 16（空狀態圖示磚）、full（chip、開關）。巢狀時內層 ≈ 外層 − 內距。
- **字級**：`text-title` 24/32（600）、`text-page` 20/28（600，頁標題）、`text-section` 16/24（**不含字重**，標題自己加 `font-semibold`）、`text-reading` 15/26、`text-body` 14/22、`text-data` 13/20（表格、inspector、選單）、`text-caption` 12/18、`text-metric` 20/28，VPN Manager 另有 `text-micro` 11/16（鍵帽、密集的 mono 值）。系統字體（含 PingFang TC／Noto Sans TC），不下載字型；中文不加字距、不全大寫。**機器值**（ID、位址、埠、金鑰指紋、計數、時間）一律 `.machine`（mono＋tabular-nums＋任意處換行）或 `code`。
- **圖示**：只用 lucide（全域 1.75 筆畫、`currentColor`）：按鈕內 16px、導覽與頁首圖示磚 18px、密集標頭與選單 14px；只有目前的導覽項目以外殼共用的 `#vpnm-brand-gradient`（`userSpaceOnUse`）描邊。圖示旁的文字讓圖示 `aria-hidden`；只有圖示的按鈕有 `aria-label` 與 `title`。
- **兩種密度**：品牌時刻（外殼、空狀態、讀取、主要按鈕、目前位置、浮層）可以有光、漸層與玻璃；工作台內容（表格、表單、inspector、圖表、程式碼）一律清楚、實心、不發光。效果與效率衝突時選效率。

## 5. 三個簽名

1. **保護狀態列**：每個 Instance 一條橫向狀態（相位圖示＋中文狀態＋enforcement 證據＋出口位置＋即時速率 sparkline），一眼看出「哪些流量正受保護、經哪裡出去」。
2. **證據式 inspector**：每個事實標明來源與時間（例如「最後握手 12 秒前」「DNS 探測 3 秒前通過」），未觀測就寫未觀測。
3. **效果區 A — 流量拓撲**（總覽頁）：SVG 拓撲「代理埠／SSH 下載／SSH 代理／App 沙箱 → Instance → 加密 tunnel → 出口」，每個來源一個節點（即時 ↓／↑）與一條自己的線，Ready 時封包沿有流量的線與 tunnel 流動、流速對應真實速率；SSH 下載與 SSH 代理的節點圖示與線用自己的系列色（`series-ssh-pull`、`series-ssh-proxy`），代理埠節點只算一般代理流量；封鎖時路徑變暗並顯示鎖。只在可見時播放。

## 6. 元件與配方（`web/src/components/ui/*`、`components/shell/*`）

共用元件建在 `radix-ui` 原語上（Dialog、AlertDialog、DropdownMenu、Tooltip、Tabs、Switch、RadioGroup）；伺服器狀態用 `@tanstack/react-query`；class 以 `cn()`（tailwind-merge，後面的同類 utility 取代前面的）合併；共用的 class 配方在 `components/ui/look.ts`（`LIST_ROW`、`CHOICE_*`、`OPTION_*`、`ICON_TILE*`、`LIFT`、`TOOL_BUTTON*`、`METER_*`、`RISE_IN`／`STAGGER_IN`、`BRAND_HAIRLINE`…）。不引入第二套樣式系統，也不引入動畫函式庫。

- **按鈕**（`button.tsx`）：`variant` = `primary`（action 漸層＋白字＋1px 內頂光；hover／鍵盤焦點加 `shadow-glow-sm`；進行中時漸層上掃過 shimmer）／`secondary`（預設）／`quiet`／`danger`（淡紅）／`danger-confirm`（實心破壞性確認，深色字）；舊名 `ghost`＝`quiet`、`danger-quiet`＝`danger`。`size` = `md` 40px／`sm` 32px／`icon` 40／`icon-sm` 32。全部 `pressable`（按下 90ms 縮到 0.97、放開 snappy 回彈）。`pending`：`pendingLabel`＋旋轉圖示疊在同一格（寬度不變）、`aria-busy`＋`aria-disabled`、擋下重複點擊，**不設 `disabled`**（鍵盤焦點留在按鈕上）。停用時移除漸層、光暈與陰影。`IconButton`（32px，`aria-label`＋`title`；作為選單觸發時開啟中是淡漸層＋細框）、`ButtonLink`（看起來像按鈕的導覽，換頁時用 View Transition）。
- **不能用要說原因**（`action-button.tsx`）：`ActionButton disabledReason`＝`aria-disabled`（可聚焦）＋`title`＋以 `aria-describedby` 連結的 sr-only 原因，點擊無效；`ToolButton` 同樣有 `disabledReason`；選單的停用項目也可聚焦、原因寫在項目下方。
- **欄位**（`field.tsx`、`switch.tsx`、`segmented.tsx`）：`Field`（標籤、單位、說明／警告／錯誤以 `aria-describedby` 連結；錯誤保留輸入、淡入出現）；`Input`／`Select`／`Textarea` 40px（`compact`／`size="sm"` 32px）：sunken 底、line-control 邊、hover 亮一階、焦點＝青色外框貼齊邊緣＋4px 淡藍光環、`aria-invalid` 紅框、唯讀與停用各有樣式。`Switch`：開啟＝action 漸層軌道＋白色滑塊以 snappy 彈簧滑過。`Segmented`（少數平行選項：篩選、模式）：radio 語意（單一 Tab 停駐、方向鍵），選取底塊以 snappy 彈簧滑到新選項（`useThumb`），粗體不改變寬度（`StableLabel`）。
- **分頁**（`tabs.tsx`）：Radix tabs（方向鍵、Home／End，自動啟用）；底部 2px 品牌漸層指示線以 transform 滑動（`ActiveIndicator`，第一次直接就位），對應的 tabpanel 120ms 淡入；只渲染目前的 tabpanel，它是自己的捲動 owner（可聚焦，焦點是內縮 outline）。兩種大小：`page`（頁面的檢視：40px、圖示＋文字；< 480px 去掉圖示、收緊，六個分頁在 390px 仍放得下）與 `compact`（inspector／編輯器裡一個物件的檢視：36px、只有文字，最窄的 inspector 放得下六個兩字的分頁）；放不下時分頁列自己水平捲動、邊緣漸隱，頁面從不。`TabCount`：分頁上的數量（與分段的數量同一個 pill），`tone` 警告／危險表示那一頁有問題，`label` 給螢幕閱讀器讀（「目的地 1 個問題」）。選了哪一頁一律在 URL（`useTabParam`：頁面用 `view`、inspector 與編輯器用 `tab`；第一頁是預設、不寫進 URL；URL 的值不是這個物件有的分頁時顯示第一頁、不改 URL；選分頁 push 一筆歷史，返回回到上一頁）。
- **對話框與 sheet**（`dialog.tsx`）：`Dialog`（標題、一行說明、唯一捲動的內文、右下角動作列：`quiet` 取消在左、主要動作在右）、`ConfirmDialog`（破壞性時用 `danger-confirm`，內文寫明確切範圍）、`Sheet`（右側；`side="left"` 是導覽抽屜）。`material-sheet`＋頂端品牌細線；遮罩淡入＋6px 模糊；對話框 `dialog-in`（上移 12px、0.94→1，smooth 彈簧），sheet 由邊緣滑入；出場 140–180ms ease-exit，出場中立即 `inert` 且不攔截點擊。對話框靠上錨定（內容向下長，不會繞著中心跳動）。焦點：開啟時到第一個欄位（或 `[data-autofocus]`），關閉後回到開啟它的按鈕——從選單開啟時回到選單的按鈕；使用者已把焦點移到別處就不拉回（`focus-return.ts`）。
- **選單與提示**（`menu.tsx`、`tooltip.tsx`）：`material-popover`、從觸發端那一側 `pop-in`（4px＋0.96→1，snappy）；關閉立即移除、焦點先回到觸發元件。亮起的項目＝淡品牌漸層＋青色圖示，破壞性項目＝淡紅。提示同樣是 popover 玻璃，只是補充，不是事實或停用原因唯一的位置。
- **通知**（`toast.tsx`）：唯一的回饋通道，右上角、頂欄下方堆疊，**最新在上、最多 4 則**；進場 `toast-in`（bouncy 彈簧），關閉或到時的那則 `toast-out` 並 `inert`＋`aria-hidden`，其他則以 FLIP 補位（`usePresenceList`＋`useFlipList`）。成功 5 秒消失、帶後續動作的 15 秒；滑過或聚焦時暫停，離開後以剩下的時間（至少 2 秒）繼續；未確認的資訊、失敗、結果未知常駐。每則自己帶 `role="status"`／`alert`。
- **表格**（`table.tsx`）：`TableFrame` 是捲動 owner（寬表格在還有欄位的那側漸隱）；`Th` sticky、sunken 底（不透明）；列 48px，hover `bg-raised/60`，選取＝selection 底＋3px action 左線；`Tr running` 在列底畫一條不定進度的 shimmer 帶（列裡仍要有文字說明）；列第一次出現時逐列 rise-in（24ms 錯開，最多 10 列），輪詢更新不重播。表格從不發光、模糊或浮起。
- **狀態**（`badge.tsx`、`tones.ts`）：`StatusPill`（`lib/status` 的狀態：圖示〔進行中旋轉〕＋文字）、`StatusChip`（點＋文字）、`Tag`、`Dot`；色調 tone/12 底、tone/30 邊；狀態改變時色調以 snappy 過渡、圖示與文字短暫淡入（`useChangeFade`，第一次不播放）。
- **讀取、空、錯誤**（`states.tsx`）：`Skeleton`（shimmer）、`LoadingRows`（形狀同真實的列，`role="status"`）、`BrandLoading`（整頁讀取：呼吸的標誌，160ms 後才淡入）；`EmptyState`（圖示磚或 `mark`＋標題＋一兩句說明＋下一步動作，rise-in）；`ErrorState`（整塊失敗：原因、錯誤碼與 HTTP 狀態、重試；控制器連不上時是平靜的「離線」樣式而不是紅色）、`ErrorCallout`（面板或表單內的失敗）、`Callout`（就地說明：語意圖示＋文字）、`FormFailure`（衝突、結果未知、欄位錯誤）。
- **Inspector**（`inspector.tsx`、`facts.tsx`）：`EntityHeader`（40px 類型圖示磚、16px 名稱＋狀態 chip、一行說明、可複製的 ID、**動作列**）、`PropertySection`（APG accordion：高度以 `grid-template-rows` 0fr→1fr smooth 展開、箭頭 snappy、收合時立即 `inert`）、`PropertyGrid`／`PropertyRow` 與 `Facts`／`Fact`（固定 104–120px 標籤欄）、`Section`、`InspectorFooter`（固定底部的主要與次要動作＋一行狀態）。
- **工作台面板**：`Panel`（標題列＋說明＋右側動作）、`DockPanel`／`DockHeader`（36px）／`DockBody`（唯一捲動區）、`ToolStrip`／`ToolButton`（28px，`aria-pressed` 切換）／`ToolSeparator`、`Disclosure`（原生 details，支援時高度以彈簧展開）、`Expand`、`HelpButton`／`HelpText`（細節放在（?）裡，不寫成長段落）、`CircularProgress`／`ProgressTrack`（只有真實比例才給數字，否則是不定進度）、`CopyButton`。
- **指令面板**：已移除（2026-11-06）。每個動作都在它所屬的頁面、選單或通知的後續動作裡；`?do=<動作>` 網址仍由各頁的 action host 處理。
- **狀態一覽**：

| 狀態 | 做法 |
|---|---|
| hover | 120ms 換色；卡片與圖塊上浮 1px（`LIFT`），表格列只換底色，版面不移動 |
| focus-visible | 2px focus 外框，出現時從 4px 外收到 2px；密集清單與分頁用內嵌 ring；主要按鈕另加光暈；輸入框外框貼齊並加 4px 淡藍光環 |
| pressed | `pressable` 縮到 0.97；quiet 與工具按鈕另 `active:bg-sunken`；列只變暗 |
| selected／current | 淡品牌底＋漸層標記（左線、底線或光邊）＋`aria-selected`／`aria-current`／`aria-pressed`；需要時加文字 |
| disabled＋原因 | `aria-disabled`（可聚焦）＋`title`＋sr-only 原因；灰底、無漸層與光暈 |
| pending | 立即回饋：旋轉圖示＋`aria-busy`、寬度不變、不重送；長工作用進度元件 |
| success | 成功色 chip 或通知（圖示＋文字），從不用漸層 |
| empty | `EmptyState`，有下一步就給動作 |
| stale | 保留上一份資料並標示（warning 標籤、一行說明）；需要新鮮狀態的控制停用並寫原因 |
| error | `ErrorState`／`ErrorCallout`＋重試；寫入從不自動重送；結果未知時說明並提供唯讀查詢 |
| loading | `Skeleton`＋`role="status"` 文字；整頁用 `BrandLoading` |

- **沿用的行為規則**：每個控制項要嘛可用、要嘛停用並附鍵盤讀得到的原因；送出後立即 pending、防重送；失敗保留輸入並就地說明；`OUTCOME_UNKNOWN` 只提供唯讀核對（查 operation），不自動重送；412（revision 衝突）保留草稿並提供「載入最新／以我的修改覆寫」。

## 7. 動態（Mac 式彈簧；`components/ui/motion.ts`）

- **Token**（`tokens.css` 的 `@theme static`）：CSS、Radix data-state keyframes 與 Motion 共用；Motion 的 transition 只在 `components/ui/motion-tokens.ts` 由 token 換算一次（取樣的 `linear()` 彈簧以內插重現，與 CSS 完全同一條曲線），元件不寫數字。

| Token | 值 | 用途 |
|---|---|---|
| `--ease/--duration-spring-smooth` | `linear()` 取樣、620ms | 面板、對話框、sheet、換頁、側欄收合、inspector 滑入、rise-in、高度展開（不回彈） |
| `--ease/--duration-spring-snappy` | `linear()`、440ms | 選單、分段滑塊、開關、指示線、按下放開、hover 上浮、箭頭、狀態 chip、清單補位（極小回彈） |
| `--ease/--duration-spring-bouncy` | `linear()`、720ms | 通知進場（明顯回彈） |
| `--duration-fast`／`base`／`exit` | 120／180／140ms | 狀態色與焦點框／一般淡入、sheet 出場、進度寬度／出場 |
| `--ease-standard`／`enter`／`exit` | cubic-bezier | 狀態變化／一般進場／出場 |
| `--motion-shift`／`--motion-shift-panel` | 4／8px | 內容與選單的位移／面板、頁面、通知的位移 |

- **動畫 utility**：`animate-rise-in`（淡入＋上移 8px＋0.985→1，延遲 `min(--i,10)×24ms` 內建）、`animate-pop-in`（從 `--motion-pop-y` 那側）、`animate-dialog-in/out`、`animate-sheet-in/out`、`animate-drawer-in/out`、`animate-toast-in/out`、`animate-fade-in/out`、`animate-reveal`、`animate-shimmer`、`animate-glow-pulse`、`animate-spin`、`.brand-breathe`；`stagger`＋`staggerStyle(i)` 讓其他進場也逐項錯開。
- **三個獨立通道**：`transform` 給進出場 keyframes、`translate` 給 hover 上浮與拖曳、`scale` 給按壓（`pressable` 寫 `scale` 屬性）——所以可以疊加與中斷。進場 `backwards`（不保留終點，hover 與按壓仍有效），出場 `forwards`。
- **互動目錄**：按壓（`pressable`，90ms／snappy）；hover（120ms 換色、卡片上浮 1px，表格列只換底）；出現（`motion-safe:animate-rise-in`＋stagger，只在第一次出現）；同位置換內容（`playSwap` 120ms 淡入：分頁內容、狀態文字）；換頁（`<Link viewTransition>`：根 200ms 交叉淡化、主要內容 140ms 淡出、新內容上移 8px smooth；**只有換到另一頁才轉場**，同頁選物件或改 query 就地更新；不支援 View Transition 時 `useContentSwapMotion` 以 WAAPI 播 `playPageEnter`）；inspector 換物件（`playInspectorEnter`：右側 12px 滑入＋淡入）；側欄收合（`runViewTransition("sidebar")`，側欄、頂欄、主區以 smooth 彈簧變形，狀態以 `flushSync` 立即提交）；選單／提示（`pop-in`，關閉立即移除）；對話框（遮罩淡入＋模糊、`dialog-in`、出場 `dialog-out`＋`inert`）；sheet／抽屜（由邊緣滑入）；通知（`toast-in`／`toast-out`、FLIP 補位）；分段滑塊（`useThumb`，transform＋寬高，第一次不動畫）；開關（滑塊 `translate`，snappy）；分頁與導覽指示線（`ActiveIndicator`：1px 基準元素以 `translateX/Y＋scale` 定位，只動 transform）；展開（箭頭 snappy、高度 `grid-template-rows` smooth、收合立即 `inert`）；面板開合（`notePanelToggle`＋`usePanelEnter`，焦點交給新出現那側的 `data-panel-toggle`）；狀態 chip（色調 snappy＋`useChangeFade`）；進度（寬度線性 `--duration-base`；圓形進度 200ms 線性）；讀取（shimmer、`BrandLoading` 160ms 後淡入）；焦點框（4px→2px，120ms）。
- **規則**：**狀態從不等動畫**——語意狀態（開關、選取、資料、ARIA、焦點）先改、立即生效，不在 `animationend`／`transitionend` 解鎖、儲存或移焦點；稍後才移除的元素（通知）用等於出場時間的計時器並在出場開始時 `inert`。**可中斷**：中途改變目標從目前位置接續。**線性的東西保持線性**：進度、即時數值、計時不用彈簧。**不動大容器的版面**：只動 `transform`／`opacity`（與 `translate`／`scale` 屬性），小區段可用 `grid-template-rows` 展開；模糊半徑不做動畫。**沒有動畫函式庫**：CSS＋`motion.ts`（讀 CSS token 的 WAAPI）＋`look.ts` 的 class 配方。
- **動態永遠開啟**（2026-11-06 依設計規範）：沒有 `prefers-reduced-motion` 分支、`motion-safe:`／`motion-reduce:` 或減少動態的 hook；`MotionConfig reducedMotion="never"`。連續效果在頁面隱藏或離開畫面時暫停（拓撲流動、品牌場景）。
- **引擎**（2026-11-06）：Motion（motion.dev）負責 presence（`AnimatePresence`，出場中的副本 `inert`＋`aria-hidden`，`usePresenceInert`）、清單補位（`layout="position"`＋`layoutDependency`）、逐項進場（`riseVariants`＋index `custom`）、通知（bouncy 進場、`popLayout`）、分頁與同位置換內容（`swapVariants`）、數值變化（`ChangeFade`／`ChangeValue`）、面板內容滑入（`panelVariants`、`PaneSwap`）。換頁用 React 的 `<ViewTransition>`（以頁面為 key：同頁選物件不重播）；側欄收合用 typed `runViewTransition("sidebar")`。CSS 保留：`pressable`、指示線與分段滑塊（`useActiveIndicator`、`useThumb`）、Radix 對話框／sheet／選單的 data-state keyframes。舊的 WAAPI helpers（`playMotion`、`playSwap`、`useFlipList`、`usePresenceList`…）已刪除。
- **強制色彩**：面板與浮層改用 `CanvasText` 邊框、去掉背景圖與陰影；`aria-current`／`aria-selected`／`aria-pressed`／勾選的 radio 加 2px `Highlight` 外框；指示線改 `Highlight`；漸層文字改 `CanvasText`；導覽的透明邊框改為 `Canvas`（不會出現一排框）；開關、meter、拓撲線、圖例色塊維持既有的系統色規則。
- **品牌場景（three.js，2026-11-06）**：`components/scene/brand-scene.tsx`（React Three Fiber；一個 Points draw call：漂浮的訊號光點＋三條光的隧道，青→藍→靛→紫，位置在 GPU 由種子與時間算出、每格不上傳 buffer）由 `brand-backdrop.tsx` 延遲載入。只用在品牌時刻：開機與換頁載入（`BrandLoading`）、第一次使用的頁面層空狀態（`EmptyState brand`）、總覽的頁首背景；表格、表單、inspector、設定、日誌與圖表裡沒有 3D。DPR 上限 1.5（低階 1）；核心或記憶體少、或幀率持續過低時降為低階（較少光點）；頁面隱藏或離開畫面時不繪製；WebGL 不可用或出錯時只留 CSS 光暈；context 遺失時顯示 DOM 視覺、1.5 秒後以新的 context 重新掛上；卸載時 R3F 釋放 geometry 與 material。在 vpnd 的 CSP 下不需要任何放寬（無 worker、無外部資源、shader 是字串）。

## 8. 操作的聚合

1. **每個區域一個主要動作**：頁首右側放這一頁的主要動作（例如「新增連線」），對話框底部一個 `primary`，inspector 底部一個主要動作；其餘是 `secondary` 或 `quiet`。不放「看起來能按、其實沒有作用」的控制。
2. **物件的動作集中在 inspector**：常用的（啟動／停止、編輯）放在 `EntityHeader` 的動作列，這個 view 的主要動作放 `InspectorFooter`，其餘全部收進**一個**溢出選單（⋯）；同一個動作不散落在頁面各處。清單列最多一個快速動作加同一個溢出選單（與 inspector 的選單內容一致）。
3. **清單的批次動作放工具列**：作用在整個清單或選取列的動作放在 `Toolbar`／`ToolStrip` 右側（計數之後），不放在列裡或頁面其他位置。
4. **破壞性動作先預覽再確認**：`ConfirmDialog` 寫明確切範圍（會改什麼、什麼不受影響、能否復原），確認鈕用 `danger-confirm`；做不到時（例如執行中不能刪除）停用並寫出原因，而不是隱藏。
5. **同一個動作只有一個名字與一個圖示**，在選單、按鈕、指令面板與通知的後續動作中一致；通知提供的動作在它所屬的頁面也一定找得到；每個指標操作都有鍵盤做法（選單鈕、方向鍵、⌘K）。

### 8.1 頁面配方

範本是「連線」（`features/instances/*`）與「代理埠」（`features/gateways/*`）兩個清單＋inspector 頁，以及「總覽」（`features/overview/*`）這個摘要頁。其餘頁面照抄這裡的組成，不另做做法。

**動作模型**（`components/ui/action-model.ts`、`entity-actions.tsx`；每種物件一個 `features/<物件>/actions.ts`）

- 純函式 `xxxActions(物件, ctx) → ActionSpec[]` 列出物件現在提供的每個動作：`id`、唯一的 `label` 與 `icon`、`slot`（`header`＝EntityHeader 動作列，`footer`＝InspectorFooter〔第一個是 primary〕，`menu`＝唯一的 ⋯ 選單）、`danger`、`quick`（清單列的快速動作，最多一個）、`disabledReason`（不能用的原因，從不隱藏）、`pendingLabel`。狀態只改變可用性與原因，選單項目固定（連線的 ⋯ 永遠是「重新啟動、新增代理埠｜急停、刪除」）。
- 切換類動作在 header 只放適用的那一個（停止／啟動／解除急停；停用／啟用），它也是列的 quick；等使用者決定的狀態（需人工確認）同時放兩個選擇、沒有 quick。
- 綁定：頁面放一個 `XxxActionHost`（擁有該物件的對話框：編輯、確認…，同頁只有一份），`useXxxActions(物件)` 回傳加上 `run` 與 `pending` 的 `EntityAction[]`。列用 `RowActions`（quick＋⋯），inspector 用 `HeaderActions`（header 動作＋靠右的 ⋯）與 `FooterActions`；兩個 ⋯ 一定相同（`instances-page.test.tsx` 檢查）。
- 意圖類動作由 `actions.ts` 的 `sendXxx` 送出：idempotency key 以「物件＋內容」為 scope；`lib/flights.ts` 記錄送出中的意圖，列、inspector 與指令面板同時顯示 spinner，送出中的同一意圖不再送；同一物件一次一個意圖，其他意圖寫明「正在送出「…」，完成後再操作」。
- 指令面板：`xxxPaletteActions(物件, ctx)` 只列現在能用的動作（同名、同圖示），就地送出；需要對話框的開 `/<頁>/<id>?do=<動作>`，由該頁的 host 開同一個對話框並清掉參數。
- 破壞性動作一律 `ConfirmDialog`（`danger-confirm`），寫明會改什麼、什麼不受影響、能否復原；刪除後焦點回到頁標題（開啟它的列已不在）。
- 區段標頭只放作用在該區段內容的同一個動作（代理埠區段的「新增代理埠」：同名、同圖示、同一個 `run`）；導覽用 `SectionLink`（「歷史數據」），不屬於動作模型。
- 伺服器有參照保護時（仍有轉發送到的 App、仍有連線使用的設定、仍有安全設定使用的封鎖清單），「刪除」事先停用，原因寫出參照它的物件；刪除選取中的物件後，inspector 的位置顯示「選擇…」，不是「找不到…」。
- inspector 內的子清單（連入埠、裝置、程序）每列一個快速動作＋⋯，清單層級的動作放在區段標頭；view 內的建立流程是由 footer primary 開啟的對話框（每個 view 仍只有一個 primary）；狀態卡片（Provider 出口）最多一個 primary＝目前狀態的修正動作。
- 名稱後的「…」只給「開啟對話框、要再做選擇才會完成」的動作（選擇出口連線…、以一般網路重新建立出口…）；編輯、刪除這類標準動作與只問是否繼續的確認不加。
- 指令面板每種物件一組（連線、代理埠、WireGuard 設定、受管 App、轉發、DNS 設定、安全設定、IP 封鎖清單、SSH 主機）；物件清單只在面板開啟時讀取（`useXxx(enabled)`），不在每一頁背後輪詢。
- 一個動作改多個網址參數時只做一次 URL 更新（`useSetQueryParams`）：react-router 的函式更新不排隊，同一事件連續兩個 setter 只有最後一個生效（「清除篩選」曾因此只清掉狀態、留下搜尋）。

**Inspector**（`InspectorFrame`：header 與 footer 固定、區段是唯一的捲動區；很矮的視窗〔200% 縮放〕整個一起捲）

- `EntityHeader`：類型圖示磚（色調代表類型、不代表狀態：連線 info、代理埠 file、WireGuard 設定 entity）、名稱＋`StatusPill`、一行說明（位置、端點、事實標籤）、可複製的 ID、`HeaderActions`。
- 內文先放結論（`Callout`：流量現況、待套用的設定＋同一個「重新啟動」），再放 `PropertySection`（可收合，標頭有圖示與數量）＋`PropertyGrid`／`PropertyRow`（來源與時間放 `hint`）；新頁面不再用 `Facts`。
- `InspectorFooter`：`FooterActions`（這個 view 的主要動作，只有一個 primary：連線是「檢查出口 IP」、代理埠是「複製代理位址」）＋一行狀態或結果（`note`；結果以 `aria-live` 宣告）。
- **太長就分頁**（2026-11-06）：內容要捲超過約 1.5 個可視高度的 inspector 或編輯器（實測：連線、受管 App、SSH 下載、供應商帳號、安全設定），在 header 與 footer 之間改用 `InspectorFrame tabbed`＋`InspectorTabs`（compact 分頁）＋每頁一個 `InspectorTab`：分頁列固定在 header 下，每頁自己捲動。依「看什麼」分組（概況／證據／設定…），不改顯示的資料；第一頁放結論與最常看的事實。結論的規則：問題（錯誤、設定尚未套用、流量被封鎖、只設定代理變數不保護任何東西、等待 VPN、儲存失敗）在**每一頁**開頭（`lead`），一般的說明只在第一頁。表單的狀態在編輯器、不在分頁裡（切換分頁不會遺失輸入，也不會問「捨棄變更」——路徑沒變）；儲存時有問題的欄位在別頁，就切到第一個有問題的分頁、展開它的區段，並在每個有問題的分頁標上數量。只有自己一頁時，原本收合的區段（日誌、設定）預設展開。清單選另一個物件時保留分頁（清單的網址帶 `tab`），沒有那一頁的物件顯示第一頁。要向外部讀的（供應商的連入埠、裝置）在分頁開啟時才讀；在背後跟著物件更新的（SSH 下載的紀錄與日誌）由 inspector 本身失效快取，分頁沒顯示時只標成過時。內容短的（代理埠、WireGuard 設定、轉發、DNS、IP 封鎖清單、SSH 主機）維持單頁。

**清單頁版面**

- `PageHeader`：標題、一行說明、細節放 `help`／`helpText`（?）、右側一個 primary（新增）；不能用時 `ActionButton disabledReason`。
- `ToolStrip`：搜尋 → `Segmented` 篩選（附數量；太寬時 `FIT_WIDTH` 在條內捲動）→ `SortMenu` → 右側群組（`ml-auto`，換行時一起靠右）：`Count` → `ToolSeparator` → 清單層級的批次動作（`ToolButton`＋原因；影響執行中連線的先確認）。篩選、排序、選取都在 URL（`state`、`sort`、`/:id`）。
- 表格：`TableFrame selectionMarker`＋`TBody`＋`Tr`（`running` 給進行中的列），最後一欄 `RowActions`；方向鍵移動選取時以最後一次要求的列為準。

**每個元素的動態**（只用 `motion.ts`、`look.ts` 與 token）

| 元素 | 動態 |
|---|---|
| 頁面內容 | `PageHeader` → 清單 → inspector 依序 rise-in（24ms 錯開，只在開啟頁面時）；換頁另有 View Transition |
| 表格列、`PresenceList` | 第一次出現 rise-in（stagger）；入場 class 只在入場期間存在（`useEntering`），之後被移動的列只做 FLIP、不重播入場；清單已在畫面上時才加入的項目不等 stagger；離開時淡出 140ms 並 `inert`＋`aria-hidden`，之後其餘列以 FLIP（snappy）補位；篩選、排序、新增、刪除、依狀態排序時狀態改變都一樣；離開中又回來的列直接留下 |
| 選取 | 一條選取線（`ActiveIndicator`）在列間滑動（snappy），列底色 120ms |
| 清單＋編輯器 | `MasterList` 的選取線同樣滑動；窄版換面時出現的那一面 rise-in、清單列依序 rise-in，不做水平推移 |
| 報表 | 圖表增減時留下的卡片以 2-D FLIP 移位；游標讀數第一次 pop-in、之後跟著游標不加緩動；數值表展開時 reveal；切換範圍或對象時上一份資料延遲 120ms 才變暗（`aria-busy` 立即），快的回應不閃 |
| 篩選 | `Segmented` 滑塊（snappy），數量變化淡入 |
| Inspector | 換物件時 `playInspectorEnter`（右側 12px＋淡入，smooth）；即時更新不重播 |
| 數值 | 狀態 chip 色調 snappy＋`useChangeFade`；計數 `ChangeValue`；即時速率與時間不淡入（線性的東西保持線性） |
| 控制 | 按鈕、工具鈕、⋯、分段、選項卡：`pressable`；列：hover 換底、按下變暗、不縮放；文字連結 `TEXT_LINK`；拓撲節點 `LIFT`＋按下 0.98 |
| 對話框、選單、sheet、通知 | 共用元件自帶 |
| 迴圈 | 只有拓撲流動（暫停鈕與各自獨立的暫停原因）；spinner 與進行中的 shimmer 表示狀態，不是裝飾 |

狀態從不等動畫；減少動態（載入時與即時切換）取消全部動畫，離開的列立即移除，資訊不變；強制色彩下選取線、選取列、勾選的分段以 `Highlight` 標示。

**四種狀態**：讀取＝`LoadingRows`（形狀同列，`role="status"`）；空＝`EmptyState`（沒有物件：說明＋新增；篩選後沒有：compact＋「清除篩選」；inspector 未選取：「選擇…」；找不到：「它可能已被刪除」）；錯誤＝沒有資料時 `ErrorState`＋重試；過時＝重新抓取失敗但有資料時保留清單，工具列下方 `ErrorCallout`「無法更新：顯示的是 HH:MM:SS 的資料」＋重試，控制器或核心服務無法連線時意圖類動作以 `useMutationBlocked` 的原因停用。

**窄版**（≤ md 840px，也是 200% 縮放會到的寬度）：頁面左右 16px；頁首動作換到標題下方；工具列換行（數量與批次動作靠右）；inspector 在 < 1280 是右側 sheet（同一個 `InspectorFrame`）。表格依寬度讓出欄位（即時速率 < md、代理埠與所屬連線 < sm），`tableClassName="max-sm:min-w-0"` 讓剩下的欄位放進畫面；名稱換行（`[overflow-wrap:anywhere]`）；放長內容的格線用 `grid-cols-1`，不被撐寬。整頁從不水平捲動；拓撲以容器查詢重排（< 680px 代理埠在上，< 420px 節點縮窄、斷開的 tunnel 只留狀態圖示）。

**「清單＋編輯器」頁**（`MasterDetail`：DNS 設定、安全設定、IP 封鎖清單、SSH 主機、供應商帳號）

- 清單用 `MasterList`（一條選取線）＋`PresenceList`＋`ListItem actions`（與編輯器相同的 ⋯，最多一個快速動作）。
- 編輯器是包在 form 裡的 `InspectorFrame`：`EntityHeader`、結論在前、可收合的 `PropertySection`（儲存時有問題的區段自動展開）、`InspectorFooter`（「儲存」是唯一的 primary，note 寫未儲存的變更）；沒有 header 動作的物件，⋯ 放在標題列狀態旁（`TitleActions`）。無法解析的輸入算作未儲存的變更（儲存會指出問題）。
- 窄於 md 一次只顯示一面：選了物件是編輯器（上方「返回」），否則是清單、不渲染編輯器（自動開啟唯一一份的跳轉不會搶走清單）；換面是導覽，未儲存時照樣先詢問，焦點移進新出現的那一面，回到清單時回到剛才的項目。

**報表頁**（數據統計、效能統計、系統）

- 頁首下方一條全寬 `ToolStrip`，放所有決定這一頁範圍的控制（時間範圍、對象、解析度），新鮮度靠右；過時說明在它與捲動區之間。
- 內容超過一個畫面很多時，工具列下方是 page 分頁（`?view=`），每一頁是自己的捲動區、以同一條 raised 結論帶開頭（數據統計的範圍摘要、效能統計的產品摘要、系統各頁自己的結論）；分頁依閱讀時一起看的東西分（同一頁的圖共用游標）。分頁內的兩欄格線從 840px 起並排（1024px 也不必捲過整頁單欄）。
- 每個 view 以 raised 結論帶開頭，帶著這個 view 的動作（像物件的 `EntityHeader`）；沒有 inspector 的列只有快速動作。
- 圖表一個 y 軸、缺口是缺口、未知不是 0、共用以時間對齊的游標（鍵盤可操作）、可切換成表格；共用 `ChartFrame`／`ChartLegend`／`ChartTable`／`UsageMeter`。

## 9. 驗證計畫

- 原始碼：`pnpm --dir web install --frozen-lockfile`、`pnpm --dir web typecheck`、`pnpm --dir web test`（API 錯誤分類、idempotency／operation 流程、SSE、表單草稿；`motion-model`、`motion`、`cn`、按鈕、對話框焦點、選單、通知堆疊、View Transition 判斷；動作模型〔列與 inspector 的 ⋯ 相同、各狀態的停用原因、指令面板〕、表格列的 presence 與 FLIP、送出中的意圖、方向鍵以最後一次要求為準）、`pnpm --dir web build`；`cargo build -p vpnd`（嵌入 `web/dist`）。
- 瀏覽器：以隔離瀏覽器對真實 controller＋manager＋labpeer（`scripts/dev-stack.sh --seed`）走主要旅程並逐張檢視截圖：1440×900 與 1024×768、側欄展開／收合／抽屜（< 840px）、導覽指示線、分頁、對話框、選單、通知、指令面板、表格頁；並以減少動態與強制色彩各看一次。未執行的項目標 `not_run`。
- 分層（2026-11-11）：`web/src` 由下而上是 `lib`／`api`、`components`、`features`、`app`，一層只引用它下面的層（只引用型別也算）。`pnpm lint` 在 ESLint 之後以 dependency-cruiser 依 `web/.dependency-cruiser.json` 檢查這三條，另外三條是：不循環引用、沒有既不引用別人也沒被引用的檔案、`src/test` 只給測試檔用；每一條違反都讓 lint 失敗。外殼要顯示功能的內容時由 `app/router.tsx` 交給它（頂欄的即時流量條）；共用的 `queryClient` 在 `api/query-client.ts`，離開前的未儲存提醒在 `components/unsaved.tsx`。
- 審查清單：只用本文件的 token 與 utility；每個 view 最多兩個 `panel-raised`、同時只有一個目前標記發光；材質只在側欄、浮層、對話框；每個互動元件涵蓋 hover、focus-visible、pressed、selected、disabled＋原因、pending、空、錯誤；只動 transform／opacity、狀態不等動畫、減少動態時資訊不變；強制色彩下邊界、選取與開關仍看得到；繁中文字不被截斷到無法辨識、頁面不水平捲動。

## 10. 實作紀錄（v1.x 起的歷史）

> v2.0 的設計系統（§3–§8）優先：下面 v1.x 的紀錄與它衝突時（例如「不用玻璃模糊」、通知與導覽標記用 `motion` 函式庫、斷點 `md` 曾是 1024px）以 §3–§8 為準。

- **版面**：inspector 寬 340px（≥1920 為 400px）；< 1280 改為右側抽屜（Radix Dialog，焦點鎖定）。連線表格依實測改為 5 欄（名稱＋位置／端點、狀態＋流量保護、代理埠、即時速率、操作），1280 以下隱藏 sparkline 只留數值，避免水平捲動。DNS／安全設定採「短清單＋寬編輯器」（MasterDetail），編輯中離開會詢問（`useBlocker`）。
- **圖表色**：資料標記色與品牌漸層分開，經六項色彩檢查（暗色 L 0.48–0.67、CVD ΔE 9.0、對 canvas／surface／raised 對比 ≥ 3:1）：下載 `#1aa0d2`、上傳 `#8f62e2`。單一 y 軸；超過 3.5 秒的空檔或換代會斷線，不在未觀測的時間畫線；圖旁有「查看最近數值」文字表。
- **誠實狀態**：未知不是 0（速率、計數顯示「—」）；停止中的連線把上次執行的 tunnel 事實標成「上次執行」；IPv6 只說「已設定 IPv6 位址」（設定事實，非連通觀測）；控制器或 manager 無法連線時顯示全域橫幅，生命週期控制停用並寫出原因。
- **動態契約**（v1；v2 改為 §7：通知以 `usePresenceList`＋`useFlipList`、導覽標記以 `ActiveIndicator`，減少動態時取消所有動畫）：效果區 A 的虛線流動只在 Ready 且有流量時出現，速度量化為 4 級（避免每秒重播），暫停原因彼此獨立（使用者按鈕、頁面隱藏、區域不在視窗內）。
- **冪等與結果未知**：每個意圖一把 idempotency key；結果未知後以「相同內容」重送會沿用同一把 key（伺服器回原結果，不重複執行），內容改變或結果確定後換新 key。通知中的「查詢結果」只讀 `/v1/operations/by-key/{key}`。
- **CSP**：`style-src` 允許 inline（Radix 的 scroll lock 會在執行時注入 `<style>`），`script-src`、`connect-src`、`img-src` 仍只限 `'self'`。
- **尚未提供的檢視**：供應商（M6）、效能（M7）、SSH 主機（M10）在對應後端完成前不出現在導覽中，不顯示無法運作的入口。
- **第三輪審查（v1.2）**：事實合併以 `observed_at` 為準（SSE 與重新抓取誰新用誰），manager 正常時缺少的狀態不抹掉已知狀態；隱藏分頁不占事件串流（瀏覽器對同一來源只有 6 條 HTTP/1.1 連線，否則急停可能排隊送不出）；停止與急停在狀態未知時仍可用，刪除則停用並說明原因；結果未知的 idempotency key 以「範圍＋內容雜湊（FNV-1a，不保存內容）」保存在模組層級。
- **2026-10-27 審查修正（v1.3）**：
  - **預設值**：新連線預設選最新、且金鑰沒被其他連線使用的 WireGuard 設定，名稱跟著設定走，直到使用者自己輸入；匯入完成的通知與設定檢查器都有「建立連線」。
  - **無法使用的設定事先處理**：設定檔沒有 DNS 時，必須選 DNS 設定，可從預設清單一鍵建立——不在 AllowedIPs 內的預設（tunnel 送不到）會停用並說明，也可以直接輸入網段內的 DNS 伺服器；AllowedIPs 只有私有網段時，可一鍵改用（或建立）只允許這些網段的安全設定。
  - **代理埠**：建議的 port 由 manager 實際試綁（`GET /v1/ports/free`），失敗時退回本機推算；Mullvad 預設沿用一台本機有金鑰、且沒有連線在用的裝置。
  - **需要重新啟動**：常駐提示只看 manager 回報的 `running.pending_changes`，改名、地點與到期日不算。儲存後的「重新啟動使用中的 N 條連線」只在改動 worker 會用到的欄位時出現。
  - **其他**：總覽的「開始使用」第 4 步可以出現，第 1 步也可加入供應商帳號；「記憶體」改稱「連線緩衝」，並顯示實際的 TCP 連線上限；系統頁拿掉從未生效的「自動恢復」開關與「管理埠」欄位，改為說明文字、唯讀的管理位址與資料目錄。
- **數據統計（2026-10-27）**：
  - **圖表**：`components/charts/series-chart.tsx`（SVG，無新依賴）。每張圖一個 y 軸、刻度標在左側留白；速率與計數從 0 起，快取命中率固定 0–100%，延遲用對數刻度並寫明「值為所在區間的上界」。延遲的 p50／p95／p99 用同一色相的順序色（`--color-series-p50/p95/p99`，序列色的檢查通過），DNS p95 用上傳的紫色，DNS 失敗用 danger。兩條以上有圖例；每張圖都能切換成表格。
  - **缺口是缺口**：沒有資料的時間不畫線，底色標出（沒有紀錄＝淡灰，資料遺失或速率無法計算＝淡琥珀），原因寫在缺口圖例與 tooltip；重新啟動（新 generation）以 info 色直線標在它所在的時間窗中央，位置來自 API 的 `restarts`。尚未結束的最後一個時間窗寫「起（尚未結束）」，不算缺口。
  - **游標**：所有圖共用一條十字線，以時間（不是陣列位置）對齊，資料更新時不跳；圖可聚焦，←／→／Home／End 移動，Escape 離開。
  - **更新與狀態**：大約每多一個點才重新抓取（1 秒解析每 5 秒、5 秒解析每 10 秒、分鐘每 30 秒、小時每 5 分鐘）；切換範圍或對象時保留上一份並變暗；更新失敗時保留資料並寫「顯示的是 HH:MM:SS 的資料」＋重試；對象不存在時說明並提供「改看全部連線」。
  - **未知不是 0**：分位數在 +∞ 區間寫「超過 30 s」、沒有完成的連線寫原因；代理埠沒有自己的 WireGuard、DNS 與 worker 資源，選代理埠時這些圖不出現，改提供「看所屬連線」。


- **受管 App（`/apps`，2026-10-27）**：表格＋inspector（同連線頁的 SplitView）。隔離方式三選一，依 `/v1/system/capabilities` 的 `app_proxy_env`／`app_enforced_proxy`／`app_strict_netns` 啟用，不能用的寫出主機回報的原因；預設選這台主機最強的可用方式，資料晚到時重新推導、使用者選過就不覆寫。「環境變數」模式在對話框與 inspector 都常駐「不讀取這些變數的程式不受保護」。執行檔在輸入暫停 400 ms 後由 manager 檢查（`/v1/apps/executable-check`），顯示會執行的檔案（`.app` 的主執行檔）、大小與 SHA-256，建立時送出畫面上那個雜湊；之後檔案被改過，啟動被拒（`APP_ARTIFACT_DIGEST_MISMATCH`），「檢查並核准」對話框並列已核准與目前的雜湊。參數一列一個（不經 shell）並即時預覽實際 argv（`{gateway_port}`、`{app_home}` 已代入）；環境變數拒絕 `HOME`、`TMPDIR` 與代理變數並提醒不要放秘密；新增的列取得焦點，移除後焦點回到新增鈕。狀態依 `last_error.code` 命名（異常結束、已被強制停止、執行檔待核准、無法啟動…），沒有觀測時是「狀態未知」；`app_status` 事件以 `observed_at` 合併；刪除後丟掉該 App 的程序樹與輸出查詢，不再打出 404。系統頁的「擁有的資源」列出受管 App 的程序樹，「恢復」可結束 manager 重新啟動後無法確認結束的 App 程序。

- **轉發（`/forwards`，2026-11-02）**：導覽在「受管 App」之後。狀態只用 manager 回報的 `ForwardStatus`（`listening` 要 worker 以 lease 監聽才算），原因原文顯示；外部可達在觀測到外部連入前一律是中性的「未驗證」，綠色只給 `observed`。對話框依連線的供應商顯示步驟（AirVPN：網站 Client Area 保留、Local port——連線若由 VPN Manager 裡的 AirVPN 帳號建立，改為直接選連入埠，見下方「AirVPN 連入埠」；一般 WireGuard：伺服器端 DNAT），Mullvad 連線直接說明不能設定並停用送出（嚴格隔離的連線可以設定轉發，原本的拒絕已在 `c987640` 拿掉）；強制代理的 App 不能選 UDP。App inspector 的「轉發」列出送到它的轉發並可新增；自動封鎖頁與安全設定的說明改稱「轉發」並連到這頁。`forward_status` 事件以 `observed_at` 合併。

- **需人工確認的停止（2026-11-02）**：manager 重新啟動時，若有停止還沒確定寫入（`recovery_required`，原因 `STOP_NOT_CONFIRMED`），連線顯示「需人工確認」。這個狀態排在「已急停」前面，因為它要使用者先決定；原因原文顯示。inspector 提供「啟動」與「確認停止」；急停則提供「解除急停」與「維持急停」。總覽的「需要處理」寫出 manager 回報的原因。不自動選擇任何一邊。
- **200% 縮放與強制色彩（2026-11-02）**：流量路徑以容器查詢（面板寬 < 680px）改為代理埠在上、連線在下，速率分列在 tunnel 上下；寬表格在還有欄位時漸隱邊緣（捲動連動，不是動畫）；只有縮放才會到的 < md 寬度下，連線、代理埠、轉發表格把即時速率或所屬連線欄讓給名稱，名稱與詳細標題改為換行；捲動容器 `relative`，讓表格內的 sr-only 文字不逃出容器。強制色彩：目前頁面、選取列、選取的分段與分頁、按下的切換以 `Highlight` 外框標示；開關的拇指與軌道改用系統色；主要與危險按鈕保留透明邊框；拓撲線改用文字色；圖例色塊保留系列色（SVG 線本來就不被強制）；分頁焦點用 `outline-hidden`，不靠 box-shadow。
- **系統頁重新設計（2026-11-02）**：「狀態」與「診斷」改為「結論在前、事實在後」。兩者頂端各有一塊 raised 摘要（每個 view 唯一的主要摘要）：圖示圓章＋一句結論＋來源時間，下方一列事實——狀態是核心服務、即時更新、控制資料庫、指標資料庫、金鑰保管（結論依序取最嚴重者：服務無法連線 > 控制資料庫無法寫入 > 指標資料庫 > 金鑰保管 > 事件串流）；診斷是失敗／未知／警告／正常的計數，0 以灰色顯示。內容改為「主欄＋固定寬側欄」（≥1280 時並排，側欄 340／380／420px），兩欄各自堆疊，不再用兩欄格線造成的空洞；窄於 1280 時依序單欄。主機能力依「連線與代理埠／受管 App／轉發／金鑰」分組，名稱在組內不再重複前綴；受限、降級、未驗證的項目預設展開原因（`<details>`），其餘可展開；不認得的能力列在「其他」，不會消失。存取網址各占一列並可複製（萬用監聽位址列出每個主機位址）；指令只在字與字之間換行，不會斷在 `--flag` 中間。診斷新增「磁碟空間」：已用比例的 meter（`role="meter"`，含不足界線的刻度）、預留空間與為空間放棄的資料；「擁有的資源」以 2×3 計數加明細呈現，有遺留項目時提供「前往恢復」。資料庫改用共用表格元件。`Panel` 收斂為 `components/ui/panel.tsx`（系統與效能統計共用），系統頁改為開啟時才載入（主程式包 904 kB → 831 kB）。強制色彩下 meter 以 `Highlight` 填色、`CanvasText` 邊框與刻度。已用隔離瀏覽器在 1440／1280／1024／720 寬與強制色彩下檢視。
- **區網、嚴格隔離轉發與輸出紀錄（2026-11-02，在 Linux 桌機部署時發現）**：從其他主機以明文 HTTP 開啟時頁面不是 secure context：idempotency key 改由 `getRandomValues` 產生，複製在沒有剪貼簿 API 時改用 copy 指令並還原焦點。轉發對話框在選了嚴格隔離的 App、且 tunnel port 與 App port 相同時，事先說明 App 要在 127.0.0.1 監聽；轉發狀態以 `APP_WILDCARD_TUNNEL_PORT` 寫出原因與作法。App 的輸出紀錄去掉終端機控制序列（色碼、游標、標題）與其他控制字元，只留文字與 tab。
- **IP 封鎖清單的預設（2026-11-02）**：`/security/blocklists` 的內建清單有「內建」標籤、來源與條款連結、上次更新、項目數與被去掉的私有／特殊用途數量、等待原因（沒有 VPN 出口時）、啟用開關，以及復原已刪除的內建清單；安全設定編輯器為新設定預選內建清單、開啟自動封鎖並寫出優先順序；自動封鎖紀錄與連線頁把套用預設政策的連線算進去。

- **Provider 出口的重新直連（2026-11-02）**：出口卡片在 `recovery_required` 時說明原因。可以重新直連時，按鈕會開啟對話框，寫明這段時間供應商請求會經原網路送出、會看到什麼，必須勾選確認才開始；進行中顯示倒數與「取消重新直連」；不可以時顯示「不能重新直連」與原因。grant 開著時，建立連線表單的「建立後立即連線」鎖定為開（這次 run 的連線必須是 running）。
- **受管 App 的程式類型（2026-11-02）**：表單與 inspector 顯示程式類型標籤（瀏覽器、macOS App、啟動器），argv 預覽包含自動加入的資料目錄參數；不能強制代理的程式顯示「這個程式不能使用強制代理」的說明，並說明 `proxy_env` 不保證任何事。數據統計的缺口圖例新增「磁碟空間不足」。
- **本機存取埠（`/apps`，2026-11-02）**：App 對話框選嚴格隔離時沒有代理埠欄位，改為「本機存取埠」區段（`features/apps/access-editor.tsx`），先用一句話說明 sandbox 的 127.0.0.1 不是這台主機的、這裡只轉送到 App 的這個 port。一列一個埠：App 在 sandbox 內的 port → 這台主機的 port（依 App 的 port 由 `GET /v1/ports/free` 建議，使用者自己輸入後不再跟著變）、「誰能連」（只限本機／區網）；區網時填允許的網段（逗號或空白分隔）。規則鏡像伺服器的 `check_access_ports`（`features/apps/access.ts`，另檢查與代理埠衝突），伺服器的欄位錯誤（包括 `/access_ports/0/allow/1` 這種清單內的位置）顯示在該列；最多 8 列，滿了「新增本機存取埠」停用並寫明上限；新增的列取得焦點，移除後焦點回到新增鈕。每列寫出可開啟、可複製的網址（區網時另列每個主機位址）；只限本機時附 `ssh -L` 的用法，區網時以警告色寫明「App 看到的連線都來自 127.0.0.1，只憑來自本機就放行的 App 也會放行這些裝置」。inspector 的「本機存取埠」每個埠一段：`App :<port> → 127.0.0.1／0.0.0.0:<port>`、區網標籤（warning 色）、狀態（轉送中、App 未執行、重新啟動後開放、無法監聽；沒有回報時是狀態未知）、網址、允許的網段、App 是否在 sandbox 內監聽（沒有時以警告色說明轉送會失敗）、核心服務這次啟動以來的轉送與拒絕次數、最近的錯誤（danger）與最近一次拒絕。
- **AirVPN 連入埠（`/providers/:id`、轉發對話框，2026-11-02）**：AirVPN 帳號頁在「由這個帳號建立的連線」之後有「連入埠」（`features/providers/forwarded-ports.tsx`），只在 Provider 出口可用、而且不在直連期間時經網站讀取，否則寫出原因。每列：port、協定、IP 層、裝置（全部裝置或裝置名稱）、啟用與否；上方是「已用 N／5 個 · 讀取於 HH:MM:SS」與「重新讀取」；DDNS、備註與使用這個埠的轉發寫在列下；AirVPN 把它轉到不同的 local port 時，以警告色說明 P2P 程式為什麼會收不到。「建立轉發」開轉發對話框並預填（tunnel port＝local port，公開 port 與 App 的 port＝這個 port，連線預選第一條由這個帳號建立的連線），沒有這樣的連線時停用並說明；「刪除」要確認，確認框點名使用這個埠的轉發（轉發本身不刪）。保留表單是「由 AirVPN 挑選／指定」分段，指定時檢查 2049–65535 與是否已保留；滿 5 個時停用並說明。讀取失敗以 danger callout 寫出原因並可重試；登入要求驗證、帳密被拒、網站格式改變等情況另列在 AirVPN 網站上自己操作的步驟。轉發對話框：連線若由 VPN Manager 裡的 AirVPN 帳號建立，網站步驟換成這個帳號的連入埠（`features/providers/port-picker.tsx`；按下即填入 tunnel／公開／App 的 port，強制代理的 App 只填 TCP，網站上停用的埠標「已停用」），也可以直接保留一個由 AirVPN 挑選的埠；表單的公開 port 是保留的埠時，常駐「App 必須在 <port> 監聽」的說明。
- **AirVPN 連入埠的全部操作（2026-11-02：建立與測試連入埠都在 Provider 面板）**：每列有「建立轉發」「測試」「設定」「刪除」；保留表單下方有「找連續的空閒埠」（2–10，只查詢不保留），區塊底部有「檢查 DDNS」。「設定」依序是啟用、協定、IP 版本、裝置、Local port（不是公開 port 時就地警告）、DDNS 名稱（固定顯示 `.airdns.org`）、備註；只送出有改變的項目，底部的「會修改：…」是儲存鈕的說明，沒有改變或有欄位需要修正時儲存鈕停用並寫出原因；成功通知寫出 AirVPN 讀回的值，被拒絕的項目在欄位寫 AirVPN 的原因、保留輸入並重新讀取清單。「測試」開啟即測試，焦點在結果區（`aria-live`）；每條連線一列：結果（圖示＋文字，只有 AirVPN 的 ok 是綠色「連得進來」，未知字詞是中性的「結果不明（AirVPN：字詞）」，UDP 是「沒有測試」）、協定與 IP 版本、伺服器與地點、外部位址 → 送到的位址、AirVPN 的說明；沒有連線使用時列出要做的三步。DDNS 檢查每個名稱一列：指向幾條連線（0 或多於 1 為警告）與應解析到的位址。共用元件：`Segmented` 接受 `null`（AirVPN 用了這裡沒有的 IP 層字詞），`Switch` 可標記為對話框開啟時的焦點。
- **管理介面開放給區網（2026-11-02）**：以非 loopback 的 `--listen-address` 安裝時，系統頁「狀態」頂端常駐 warning callout「管理介面開放給區網」：允許的網段裡的任何裝置不需登入就能操作 VPN Manager（包括啟動受管 App），這台主機上的連線仍只接受自己的程式，以及收回的指令 `vpn-installer upgrade --listen-address 127.0.0.1`。「存取」面板的說明改為「允許的網段裡的裝置可以直接開啟這些網址」，列出監聽位址與允許的網段，並多一條更換位址的指令；`vpnctl status` 同樣寫出允許的網段與風險。


- **設計系統 v2.0（2026-11-02，第一階段：基礎）**：token、材質、彈簧與動畫 utility（`tokens.css`、`app.css`）、`cn()` 改用 tailwind-merge 並登記自訂 utility、`motion.ts`／`motion-model.ts`／`look.ts`、全部共用元件與外殼（玻璃側欄與滑動標記、44px 頂欄與麵包屑、深空底色、換頁轉場與焦點、側欄收合變形、抽屜）、指令面板與通知都已換成 §3–§8。頁面本身沿用既有的結構，因為共用元件換了外觀與互動而一起改變；以下是之後的頁面階段要依 §8「操作的聚合」逐頁改寫的部分：各 inspector 改用 `EntityHeader`（動作列）＋`PropertySection`＋`InspectorFooter`，列上的動作收斂成一個快速動作＋與 inspector 相同的溢出選單；清單頁的工具列改用 `ToolStrip` 並把批次動作放右側；頁首說明縮成一行、細節移到 `HelpButton`；各頁自己寫的色值（`rgb(…)` 邊框、`duration-[130ms]`、自製的選項卡片）改用 token 與 `look.ts` 配方；`Facts` 逐步換成 `PropertyGrid`。斷點 `md` 由 1024px 改為 840px：表格在 840–1023px 之間也顯示原本只在 ≥1024px 出現的欄位。
- **設計系統 v2.0（2026-11-03，第二階段之一：範本頁面）**：連線、代理埠、總覽依 §8.1 改寫，其餘頁面照抄。新的共用元件：動作模型（`action-model.ts`、`entity-actions.tsx`）、送出中的意圖（`lib/flights.ts`）、`TBody`／`PresenceList`、`TableFrame selectionMarker`、`InspectorFrame`、`SectionLink`、`SortMenu`、`ChangeValue`、`PageHeader help`、`ToolButton pending`、`FIT_WIDTH`／`TEXT_LINK`。行為改變：連線列的 ⋯ 與 inspector 相同（「重新啟動、新增代理埠｜急停、刪除」；編輯改在 inspector）；代理埠列有停用／啟用與 ⋯；已停用而沒有回報的代理埠顯示「已停用」；兩頁都可篩選與排序；連線清單有「重新啟動待套用」（先確認）；指令面板的物件動作由動作模型產生，需要對話框的開該頁的 `?do=`。修正：`Menu` 的 `label` 被 Radix 的 `aria-labelledby` 蓋掉；沒有開啟者的對話框關閉後焦點回到頁標題；方向鍵連按以最後一次要求的列為準。已用隔離瀏覽器在 1440／1280／1024／800／390 寬、減少動態（載入與即時切換）、強制色彩與連按下檢視。
- **設計系統 v2.0（2026-11-03，第二階段之二：供應商與 WireGuard 設定）**：依 §8.1 改寫。WireGuard 設定的動作模型（`features/profiles/actions.ts`）：header「編輯」「更換伺服器」、footer「建立連線」（primary，也是列的快速動作）與「檢查設定」、⋯「刪除」；匯入的一般設定「更換伺服器」停用並寫原因，有連線使用時「刪除」停用並寫出條數。工具列有搜尋、使用中／未使用篩選、排序與計數；inspector 為 EntityHeader（entity 色、狀態＝到期或使用情形）＋身分／對端／介面／使用中的連線／來源，「檢查設定」的結果放在內文最上方；匯入預覽改用 PropertyGrid；指令面板列出 WireGuard 設定與其動作。供應商的帳號、連入埠、裝置與 Provider 出口各有動作模型（`features/providers/actions.ts`）：帳號列「重新讀取帳號」＋與帳號頁相同的 ⋯（「移除帳號」在這個帳號建立的 WireGuard 設定還在時停用並說明），選取線在帳號間滑動；帳號頁改為 inspector 結構，footer「建立連線」開對話框（伺服器清單開啟時才經 Provider 出口讀取）；連入埠每列「測試」＋⋯（建立轉發、設定｜刪除），區段標頭「重新讀取連入埠」；Provider 出口卡片只有一個 primary，「變更…」統一為「選擇出口連線…」，不能檢查時「檢查出口」停用並寫原因；伺服器、出口與連入埠的選擇改用 `look.ts` 配方。窄於 md 時出口卡片與帳號一起捲動。修正：功能檢查在連入埠讀完後要等下一次輪詢才更新——每個 AirVPN 網站操作結束時重新讀取 Provider 出口狀態；刪除連入埠或撤銷裝置後焦點回到頁標題。共用元件：不能用的按鈕、工具鈕與選單項目在強制色彩下以 GrayText 標示。已用隔離瀏覽器在 1440／1280／1024／800／390 寬、減少動態（載入與即時切換）、強制色彩、連按與一個實際安裝的唯讀資料下檢視。
- **設計系統 v2.0（2026-11-03，第二階段之二：受管 App、轉發）**：兩頁照 §8.1 改寫。受管 App：標頭「停止／啟動」（列的快速動作）與「編輯」，底部主要動作「檢查並核准執行檔」，⋯ 為「重新啟動、新增轉發｜刪除」；不能用時寫出原因（主機不支援的隔離方式、執行檔待核准、仍有轉發送到它時不能刪除並列出轉發）。清單有狀態篩選、排序與批次「重新啟動待套用」（先確認）；inspector 先放結論（只說實際套用的隔離方式允許的網路，環境變數模式常駐不受保護的說明），再放執行、程序樹、監聽的連接埠、本機存取埠、轉發、輸出紀錄、資源上限、執行檔、設定；對話框的隔離方式與協定改用範本的選項卡，參數、環境變數、可寫入目錄與本機存取埠的列以 PresenceList 出現、離開與移動。轉發：標頭「停用／啟用」與「編輯」，底部主要動作「測試連入」（請 AirVPN 從伺服器連到公開 port，結果以 AirVPN 的字詞寫在底部，只有「連得進來」是綠色），⋯ 為「前往目標 App、前往所屬連線｜刪除」；篩選（全部／監聽中／未監聽／已停用）與排序；編輯 AirVPN 連入埠上的轉發時顯示該埠已選。指令面板加入兩種物件（只在開啟時讀取）。修正：清除篩選與關閉新增轉發一次更新 URL；刪除選取中的物件不再先閃過「找不到…」；表格與 PresenceList 的列只在第一次出現時 rise-in（排序時被移動的列曾淡出再淡入），之後加入的列不等 stagger。已用隔離瀏覽器在 1440／1280／1024／800／390 寬、減少動態、強制色彩、連按與一個實際安裝的唯讀資料下檢視。
- **設計系統 v2.0（2026-11-03，第二階段之二：政策與 SSH 頁）**：DNS 設定、安全設定、IP 封鎖清單、自動封鎖紀錄、SSH 主機依 §8.1 改寫。`MasterDetail` 窄於 840px 時一次只顯示一面：選了物件是編輯器（上方「返回」），否則是清單且不渲染編輯器（自動開啟唯一一份的跳轉不會搶走清單）；換面是導覽，未儲存時照樣先詢問，焦點移進新出現的那一面，回到清單時回到剛才的項目。清單用 `MasterList`（一條選取線滑動），列上有與編輯器相同的 ⋯。動作模型：DNS／安全設定＝儲存、⋯ 刪除（有連線使用時寫明原因）；IP 封鎖清單＝停用／啟用（列的快速動作）、編輯、立即更新（網址）或更新內容（上傳），⋯ 刪除，編輯與更新內容改為對話框；封鎖紀錄＝「解除封鎖」（先確認）、⋯ 複製來源位址、前往所屬連線；SSH 主機＝測試連線、儲存、⋯ 移除，`~/.ssh/config` 的區塊是唯讀 inspector，唯一動作是「讓它經 VPN」。DNS 與安全設定在 manager 回報仍有連線用先前版本時，結論先寫出並提供與儲存通知相同的「重新啟動使用中的 N 條連線」。修正：無法解析的輸入算作未儲存的變更（儲存會指出問題）、DNS 數字欄不再靜默改回舊值、長麵包屑不再撐寬窄視窗、強制色彩下 `aria-disabled` 控制改用 GrayText。已用隔離瀏覽器在 1440／1280／1024／800／390 寬、減少動態（載入與即時切換）、強制色彩與連按下檢視，並以唯讀方式看過一個實際安裝的資料。
- **設計系統 v2.0（2026-11-03，第二階段之二：數據統計、效能統計、系統）**：依 §8.1 改為報表頁。頁首一行說明＋（?）；其下一條 `ToolStrip` 位於它影響的所有內容之上：時間範圍、對象（數據統計為選單，找不到的對象仍列出並標「找不到」）、右側解析度與更新時間；更新失敗時工具列下方寫「無法更新：顯示的是 HH:MM:SS 的資料」＋重試；切換時上一份資料延遲 120 ms 才變暗（`aria-busy` 立即）。效能統計的趨勢改用共用 `series-chart`（缺口底色、同面板共用游標、表格），範圍只在工具列一處；連線表格有滑動選取線（`?instance=`，↑／↓），展開代理埠以 presence 進出，選取連線的趨勢在表格下方、換連線時由右滑入。新共用元件 `ChartFrame`／`ChartTable`／`UsageMeter`；游標讀數改為 popover 玻璃、鍵盤聚焦時以 `aria-live` 讀出；強制色彩下軸文字 `CanvasText`、格線與缺口為淡化 `CanvasText`、游標 `Highlight`。數據統計分解表可依欄位排序（`aria-sort`，列以 FLIP 換位），目前對象為選取列；圖表增減時留下的卡片以 2-D FLIP 移位。系統各分頁以 raised 結論開頭並帶該頁動作（`features/system/actions.ts`）：診斷「重新診斷」「下載 JSON」；恢復新增結論（可清理＞無法檢查＞只回報）、「重新檢查」「清理 N 個項目」，每個遺留項目有自己的「清理」（只回報者寫原因），確認框列出確切項目與路徑，一次一個清理，清理後項目淡出補位。`Facts` 全換成 `PropertyGrid`；窄版表格讓出次要欄位；每秒時鐘只在顯示相對時間的小元件內。已在 1440／1280／1024／800／390、減少動態、強制色彩、連按與一個實際安裝的唯讀資料下檢視。
- **設計系統 v2.0（2026-11-03，第二階段：整合）**：四組合併後，指令面板加入 DNS 設定、安全設定、IP 封鎖清單與 SSH 主機（只在開啟時讀取，動作與編輯器相同）；`useSetQueryParams` 讓一次改多個網址參數只導覽一次（連線、代理埠、WireGuard 設定、受管 App、轉發的「清除篩選」）；複製按鈕的名稱在拉丁字前加空格（「複製 DNS 設定 ID」）。恢復檢查（後端）：socket 屬於仍存活、身分已驗證的遺留 worker 時一律列為「仍持有」、只能隨 worker 一起結束（macOS 上 accept 佇列滿的 socket 拒絕連線的方式和沒人持有的一樣，卡住的 worker 曾被判成可清理）；連線探測被拒時重試 3 次（間隔 50 ms）才算沒人接聽。已知待處理：`ReconcileAction` 沒有路徑，結果以送出時的檢查命名；封鎖清單的 `waiting` 說明沒有原因碼，前端以文字去重。
- **App 沙箱的流量（2026-11-06）**：嚴格隔離的 App 走 sandbox 的 TUN，不經代理埠，之前在畫面上沒有任何流量（一個實際安裝上，有個 App 每小時 12.4 GB，總覽卻寫 0 bps）。現在連線的 payload 包含它（後端，架構 §4.3、§6），另外以「App 沙箱」標出：同一條連線的嚴格隔離 App 共用一個 sandbox，分不出各個 App，所以一律以 sandbox 為單位、並寫明是它們合計。總覽的下載／上傳第二行「含 App 沙箱 54.9 Mbps」（只在有 sandbox 時出現，單獨一行，數字不會被截斷）；流量路徑在代理埠旁畫一個 App 沙箱節點（App 名稱、第一個 App 的連結、↓／↑ 各一行，沒有新的樣本時是 —），寬版的來源欄固定 150px、不換行（換行的 flex 欄會被最寬節點的文字撐開，節點壓到連線方塊上，瀏覽器實測時發現）；數據統計分解表在連線底下列「App 沙箱」（自己的量與峰值，延遲寫「不經代理連線」、可用率寫「同所屬連線」，圖表鈕改看所屬連線），摘要與流量圖的游標讀數寫出其中 App 沙箱的部分；嚴格隔離 App 的 inspector 有「流量」：sandbox 的即時速率、追蹤中的流、流量表淘汰與因表滿拒絕的次數（拒絕是 warning），與其他 App 共用時先寫明。已用隔離瀏覽器對有嚴格隔離連線、兩個 App 與代理埠流量的 dev stack 檢視 1440／1024／640／390 寬與強制色彩加減少動態。2026-11-07：經轉發連入的連線也算進 App 沙箱與連線的流量（嚴格隔離的轉發都送進 sandbox；之前 BitTorrent 經轉發的下載完全沒有顯示，總覽接近 0 bps）。受管 App 的概況在「程序數」後多一列「流量」：App 沙箱最近一秒的 ↓／↑（葉元件，自己的時鐘與即時速率，只有這一列每秒重繪），沒有數據時是「—」並寫出原因；「流量」分頁、流量圖副標、摘要的說明、頂欄 popover 與總覽的說明都寫明含轉發。截圖檢視：dev stack（嚴格隔離連線、strict echo App、TCP 轉發、lab 經轉發連入）1920×1080 與 1512×982 的總覽（含說明）、頂欄 popover、數據統計、App 概況（含連線停止時）與流量；1512 寬時概況的說明在「連入」中間斷行，改短。
- **轉發的 PROXY protocol（2026-11-06）**：轉發對話框在「啟用」之下、同一張卡片裡加「把來源位址傳給 App（PROXY protocol v2）」開關（與代理埠對話框的「允許 UDP」同一個做法）：說明每條 TCP 連線開頭會先送真正的來源位址（否則 App 看到的都是本機位址），App 必須支援 PROXY protocol v2、否則連線會失敗；TCP＋UDP 時另寫 UDP 照常轉送。只轉發 UDP 時開關關閉並停用、就地寫出原因，使用者原本的選擇在改回 TCP 時恢復，請求從不對只轉發 UDP 的轉發開啟；伺服器在 `/proxy_protocol` 的拒絕顯示在開關下方。編輯時從儲存的選擇開始，啟用／停用（列、inspector、指令面板）與 `vpnctl` 都原樣保留它。inspector「設定」多一列「來源位址」（以 PROXY protocol v2 傳給 App／不傳給 App），監聽中的結論寫出 App 先收到標頭。已在 dev stack 以 1440×900 檢視 inspector、編輯對話框與只轉發 UDP 時的開關。
- **太長的頁面與 inspector 改成分頁、頂欄改為即時流量（2026-11-06）**：太長的頁面都改成分頁；頂欄的搜尋與操作紀錄拿掉，加上流量資訊。以 dev stack（兩條執行中的連線、一條嚴格隔離連線的兩個 App 沙箱、代理埠流量、轉發、SSH 下載工作）與一個實際安裝的唯讀資料，量每個捲動區的內容高度／可視高度：1440×900 下受管 App inspector 5.5–7.3 倍、連線 inspector 3–4.1、供應商帳號 3.9、數據統計 3.2（1024×768 是 6.6）、效能統計 2.6（3.9）、系統 診斷 2.4（5.0）、安全設定 2.6（3.7）、SSH 下載 2.5（還沒有紀錄時）；轉發 2.4–2.7、WireGuard 設定 2.2、SSH 主機 1.8（實際 Include 已加入時）、DNS 1.6、代理埠 1.5、IP 封鎖清單 1.3–1.5、自動封鎖紀錄與總覽不需捲動。前者改成分頁（見 §2、§6 分頁、§8.1「太長就分頁」與報表頁），後者維持單頁。改後 1440×900 每個分頁 ≤ 1.6 倍，1024×768 ≤ 2.1 倍（例外：受管 App 的「設定」在參數很長時照樣長，資料本身就是那樣；SSH 下載的「設定」2.3；系統「操作紀錄」是 50 筆的紀錄清單）；390px 頁面不水平捲動，六個 page 分頁放得下。頂欄：即時流量條取代指令面板鈕與最近操作（見 §3）；最近操作移到「系統 › 操作紀錄」（`features/system/operations-list.tsx`，原 `components/shell/operations-drawer.tsx`），指令面板也有「最近操作」。轉發 inspector 的供應商連結直接開帳號的「連入埠」分頁。
- **轉發的 UDP 直接送進沙箱（2026-11-06）**：轉發對話框在 PROXY protocol 之下、同一張卡片裡加「UDP 直接送進沙箱」開關：說明 UDP 不經本機位址轉送、datagram 原樣送到 App 自己在 tunnel port 的 socket（App 看到真正的來源並從同一個 port 回覆，Kad、DHT 需要），App 要在所有位址（0.0.0.0）或 tunnel 位址接收、App 的 port 必須等於 tunnel port，來源同樣經 IP 封鎖清單與自動封鎖；TCP＋UDP 時另寫 TCP 照常轉送。不能用時（只轉發 TCP、連線不是嚴格隔離、App 不是嚴格隔離）開關關閉並停用、就地寫出是哪一個原因，使用者的選擇保留到條件回來，請求從不對不能用的轉發開啟；App 的 port 與 tunnel port 不同時在開關下方寫出、不送出；伺服器在 `/udp_direct` 的拒絕也顯示在開關下方。嚴格隔離 App 的提示依設定改寫：TCP＋UDP 且直接送進時「TCP 在 127.0.0.1、UDP 在所有位址接收」，只有 UDP 時「要在所有位址接收 UDP」。inspector「設定」多一列「UDP」（直接送進沙箱／經本機位址轉送，只在轉發帶 UDP 時出現），「受管 App」的提示寫出各協定由誰接收，「來源位址」在只有 UDP 帶真正來源時如實寫出；監聽中的結論分開寫 TCP 送到 127.0.0.1、UDP 由 App 自己的 socket 收到。PROXY protocol 開關在 TCP＋UDP 且 UDP 直接送進時寫「UDP 不加標頭（直接送進沙箱，見下方）」，不再說 UDP 照常轉送。啟用／停用與 `vpnctl` 原樣保留它。已用隔離無頭瀏覽器在 dev stack（嚴格隔離連線、App 在 127.0.0.1 收 TCP、在 0.0.0.0 收 UDP）以 1440×900 與 390×844 檢視 inspector 各區、編輯與新增對話框的各種狀態。已知：轉發清單的「目標」欄（`forwards-page.tsx`）對只轉發 UDP、直接送進沙箱的轉發仍寫 `127.0.0.1:<port>`，留給頁面版面的工作一起改。
- **動態層與主視覺（2026-11-06）**：移除指令面板；Motion 動態層（`motion-tokens.ts`）、React `<ViewTransition>` 換頁、移除所有減少動態分支；右側詳細面板可收合並記住；three.js 品牌場景（開機與換頁載入、第一次使用的頁面空狀態 `EmptyState brand`、總覽背景）；index.html 靜態開機畫面；每頁一個 chunk、vendor chunk；1 秒時鐘與即時速率移到葉元件（`RelativeTime`、`LiveTotals`、`useInstancesSelect`）。以 dev stack 在 1920×1080 與 1512×982 檢視所有頁面；修掉場景太暗、空狀態只占面板上緣、即時速率圖的軸標被線蓋住、「涵蓋 n %」斷行。
- **數據記錄的狀態（2026-11-07）**：一台主機的磁碟寫滿後指標停止記錄，數據統計只是一片空白、沒有任何說明。現在指標在磁碟滿時改為覆蓋最舊的資料、照常記錄（架構 §6「磁碟空間」），畫面只在需要時說明：`GET /v1/system/status` 的 `store.metrics_recording` 是 `overwriting` 而且已經覆蓋過資料（或有樣本連覆蓋都放不下）時，數據統計的工具列下方出現 warning `Callout`「磁碟已滿，已覆蓋最舊的紀錄」（可用空間大於 0 時是「磁碟空間不足，…」）：新的數據照常記錄、從何時起提前刪除了幾筆最舊的資料、圖上標為「磁碟空間不足」、可用空間與恢復正常保存的門檻，以及「查看磁碟空間」（系統 › 執行環境）；寫入失敗（`failing`，持續 5 秒以上）時是 danger「數據無法寫入」與原因。提示是葉元件（`features/metrics/recording.tsx`，自己的每秒時鐘），以 Motion presence 淡入淡出（頁面開啟時已在就直接顯示），`role="status"`；每個分頁都看得到。總覽的「需要處理」列一項「數據統計」（同一句話，沒有時鐘），摘要的「需要處理」計數也包含這些系統項目（之前只數連線，和清單對不上）；原本「儲存」那項只看控制資料庫。缺口圖例「磁碟空間不足」的說明改為覆蓋最舊的資料；系統 › 執行環境的「磁碟空間」列出兩份保留空間（控制資料、指標）與「為空間覆蓋的資料」。截圖檢視（隔離 dev stack，64 MiB tmpfs 寫滿）：數據統計 1920×1080 與 1512×982 的覆蓋中（可用 0 B 與 8 MiB）、寫入失敗與恢復後，總覽兩種尺寸，系統 › 執行環境的正常與覆蓋中；當時修掉：連結原本指向沒有磁碟卡片的「診斷」、時間後多一個空格、寫入失敗時連結改為「查看指標寫入」。
- **總覽的流量圖（2026-11-07）**：流量路徑下面加一張圖（`features/overview/traffic-chart.tsx`）：所有連線的 payload（下載、上傳，bit/s），範圍 15 分鐘／1 小時／6 小時／24 小時（與數據統計同名；面板標題列的分段控制，這個瀏覽器記住上次的選擇）。先畫已保存的數列（`GET /v1/metrics/series?scope=all`：同樣的格點、缺口帶與重新啟動線，與數據統計的「流量」同一個 `SeriesChart`），最後一個保存的窗之後用事件串流的即時樣本補到主機的現在（`features/overview/traffic`：每個窗是各連線在窗內樣本平均的和，與 scope all 的定義相同；保存還沒寫到的最新窗也由即時樣本補，已量到的不覆蓋；新的 worker 世代畫重新啟動線）。時間全以主機的時間計（`useServerNow`），右緣就是主機的現在。沒有資料的時間留白不畫 0，游標讀數寫原因（缺口的原因、「沒有即時樣本」、「即時樣本，尚未存入」）；App 沙箱的部分在讀數裡逐點寫出，圖例旁寫這段範圍裡 App 沙箱占的比例。（SSH 的兩條線見下一條。）換範圍時上一份資料變暗留著；「表格」開關（最新的 360 列）、←／→ 逐點、「在數據統計查看」連到同一個範圍。高度：螢幕高 ≥ 1040px 時圖 300px，否則 236px——1512×982 下整張圖與右欄的需要處理都在第一屏。
- **SSH 下載與 SSH 代理另外顯示（2026-11-07）**：總覽裡 SSH 下載與 SSH 代理各自顯示，不和一般代理混在一起。代理埠現在把 SSH 分成兩類計數（架構 §7c）：SSH 下載（VPN Manager 的 SSH 下載工作）與 SSH 代理（`vpnctl ssh-proxy` 與到 22 埠的連線），兩者不重複，其餘是一般代理流量；兩類都有保存的數列。**顏色**：`--color-series-ssh-pull` #c98500 與 `--color-series-ssh-proxy` #d55181，與下載、上傳兩色一起在 #0b1120 上全部成對驗證（亮度帶 L 0.48–0.67、最差的 CVD ΔE 9.0 是原本的下載↔上傳、一般視覺 ≥ 18.8、對比 ≥ 3:1）；只用在資料記號（線、節點圖示、色點），文字仍用文字色。**流量路徑**：每條連線的來源依序是代理埠（只算一般代理流量；`portKinds` 從速率減去兩類 SSH）、SSH 下載（經這條連線代理埠的工作；「進行中／全部 個工作」，進行中＝連線、列出或下載中；只有一個工作時連到它）、SSH 代理（經這條連線代理埠的 SSH 主機，或有開著的 SSH 連線時出現；「N 條連線」，連到 SSH 主機）、App 沙箱。每個節點兩行（名稱與計數；↓／↑），44px 高；來源欄改為 196px，最寬的一對速率放得下一行，所以節點不再是三行。每個來源有自己的一條線：代理埠與 App 沙箱用品牌藍，SSH 下載、SSH 代理用自己的顏色；連線就緒時，有流量的來源的線上有移動的虛線（與 tunnel 同一個 `topo-flow`，同樣受暫停動畫、隱藏頁面與捲出畫面控制，流速依那個來源的速率），沒有在跑的來源節點是虛線框。說明文字依實際有的來源寫（「本機代理埠、SSH 下載與 SSH 代理 → 連線 → …」）。**流量圖**改為上下兩張小圖「↓ 下載」「↑ 上傳」（共用一個游標；每張自己的刻度，螢幕高 ≥ 1040px 時各 156px，否則 124px），每張畫全部 payload 與其中的 SSH 下載、SSH 代理（虛線，蓋在全部的線上時兩者都看得到；`ChartSeries.dash`，圖例與讀數的色塊也是虛線）；一張圖裡每條線都是同一個方向，SSH 代理的上傳不會被藏起來。圖例旁寫範圍內 SSH 下載、SSH 代理與 App 沙箱的比例（有流量的才寫），讀數另寫該方向 App 沙箱的部分；表格有六欄。**頂欄 popover**：每條連線在合計下列出「其中 SSH 下載」「其中 SSH 代理（N 條 SSH 連線）」與 App 沙箱，有流量才出現，色點與流量路徑相同。**數據統計**：摘要的下載、上傳第二行「其中 App 沙箱…、SSH 下載…、SSH 代理…」（名稱與數字不拆行）；流量圖讀數另列 SSH 下載、SSH 代理（有流量的點）；各連線分解表在連線下多「SSH 下載」「SSH 代理」兩列（範圍內有流量時；峰值是自己的，延遲寫「算在代理埠」、可用率「同所屬連線」，圖表鈕看所屬連線），代理埠列減去它的 SSH（副標「不含 SSH」，峰值用 `peak_non_ssh_*`），所以各部分加起來就是連線的總量。代理埠與連線的 inspector 把原本的「其中 SSH」分成「其中 SSH 代理」「其中 SSH 下載」兩行。截圖檢視：dev stack（lab peer 把 tunnel 內 2222 埠轉到本機的 sshd；連線下載上限 40 Mbps；一個 SSH 下載工作、兩條 `vpnctl ssh-proxy` 連線各下載與上傳、兩個代理埠上的一般流量）1920×1080 與 1512×982 的總覽（含讀數）、頂欄 popover、數據統計摘要與各連線、代理埠與連線 inspector、工作暫停與連線關閉後的閒置節點；1512×982 下流量路徑、兩張圖與需要處理都在第一屏。
- **側欄重新分組、每組可以收起（2026-11-07）**：原本「工作區」一組九項（總覽、連線、供應商、WireGuard 設定、代理埠、受管 App、轉發、SSH 主機、SSH 下載），改為總覽單獨在最上面，其餘分成出口、代理與 App、SSH 三組，觀測、政策、主機不變；每組可收起（見 §3 側欄）。截圖檢視：1920×1080 與 1512×982 的展開、收起兩組（其中一組有目前頁面：只剩它一項、組名寫收起的數量）、到收起的組裡的頁面（那一項出現，其餘仍收著）與圖示軌（全部項目與分隔線）。
- **App 的停止前等待與寫入限制（2026-11-07）**：區塊鏈節點、錢包這類程式要成為嚴格隔離的受管 App，需要存檔的時間與原本 systemd unit 的檔案保護。App 對話框新增「停止前等待（秒）」（1–900，預設 10，提示寫明用於停止、重新啟動與核心服務停止，錢包與資料庫設長一點）與嚴格隔離專用的「限制寫入位置」開關；開啟時顯示「可寫入的目錄」清單（與強制代理同一個編輯器，說明改為節點或錢包的資料目錄），關閉時隱藏。App 設定分頁列出「可寫入」（私有目錄、各目錄，嚴格隔離另註明其他地方只能讀、含 /dev；沒開啟時寫「它的使用者能寫的任何地方」）與「停止前等待 N 秒後強制結束」。停止需要較久時，停止按鈕最多 20 秒就回來，App 顯示「停止中」直到它結束。
- **SSH 下載的日誌與傳輸紀錄可以清除、可以不記錄檔名（2026-11-07）**：檔名可能敏感，所以紀錄要能清除。工作多兩個動作「清除傳輸紀錄…」「清除日誌…」：在動作模型的 ⋯ 選單破壞性那一組（與「刪除」同一組，危險色），也以 ToolButton 放在「紀錄」「日誌」分頁的區段標題列（同一個名稱、圖示與對話框；送出中顯示進度）。兩者都先開確認對話框寫清楚範圍：永久刪除、資料庫裡不留內容；傳輸紀錄只清完成與失敗的，未完成的 N 個檔案保留紀錄會接著下載；不會刪除或移動任何檔案（寫出本機資料夾），另一種紀錄不受影響；清除後無法復原。完成後提示刪了幾筆，日誌只剩一行「已清除日誌（N 行）」。工作的編輯對話框在「行為」之後多一組「紀錄」：開關「在日誌與傳輸紀錄中記錄檔名」（關掉時說明完成的檔案只留傳輸編號、未完成的在完成前保留檔名、下載中的仍即時顯示但不保存；原本記錄檔名的工作關掉時提醒先前的紀錄仍有檔名、可以清除）與「保留天數」（1–3650，空白＝只保留最新的 500 行與 1,000 筆）。inspector「設定」分頁多「紀錄」區段（檔名、保留）；紀錄分頁的頁尾寫保留方式；不記錄檔名的紀錄列以等寬字顯示傳輸編號並註明「未記錄檔名」，不顯示本機路徑。截圖檢視：dev stack（lab peer 把 tunnel 內 2222 埠轉到本機的 sshd，四個檔案下載完）1920×1080 與 1512×982 的紀錄分頁與清除確認、清除後的空紀錄與提示、日誌分頁（清除後的一行與只有傳輸編號的新紀錄）、⋯ 選單、「設定」的紀錄區段與編輯對話框的「紀錄」。
- **DNS 設定全部失敗時的備援、各伺服器的原因與 NextDNS（2026-11-07）**：連線的 inspector 在每個分頁開頭多一個警示（危險以外最高的一級）「DNS 設定的伺服器都沒有回應」：寫明暫時改用 WireGuard 設定宣告的 DNS、查詢同樣只經 tunnel、但這段時間不經那份 DNS 設定的伺服器（它的過濾與紀錄不適用）、恢復後自動改回，下面逐行列出每個伺服器與原因（`DoH 45.90.28.0:443 4.0 秒內沒有回應`），動作「檢查 DNS 設定」連到那份設定。「證據」的「DNS 探測」：備援時寫「通過，改用 WireGuard 設定的 DNS」（原因在上方的警示；worker 停止後才列在這裡），失敗時「失敗」下逐行列出原因（不再擠在一行）。連線清單與總覽的「需要處理」也列出備援中的連線。DNS 設定的編輯器：伺服器區的說明加上全部沒有回應時的備援；查詢期限的提示加上「經遠的出口使用 DoT 或 DoH 時，建議 5000 以上」；「常用伺服器」選單在單一伺服器的預設之後（分隔線）多一項「NextDNS（設定 ID）…」，開啟對話框輸入設定 ID（6 個十六進位字元，大寫自動轉小寫）與選填的裝置名稱（英數字與連字號、不在頭尾、最多 56 字元，DoT 的伺服器名稱放得進一個 DNS label），即時預覽四個伺服器（DoH 45.90.28.0:443、45.90.30.0:443 `https://dns.nextdns.io/<ID>/<裝置>`；DoT 45.90.28.0:853、45.90.30.0:853 `<裝置>-<ID>.dns.nextdns.io`），「套用」取代伺服器清單、名稱空白時填入「NextDNS（ID）· 裝置」，按「建立」或「儲存」才生效（選單在伺服器滿 4 個時仍可開，單一伺服器的項目則寫明上限）。截圖檢視：dev stack（DNS 設定指向 lab tunnel 到不了的 NextDNS 位址，備援是 lab peer 的 DNS）1920×1080 與 1512×982 的連線清單、證據分頁與警示，DNS 設定的選單、NextDNS 對話框（預覽）與套用後的編輯器。
- **每個 Provider 的入口與出口（2026-11-08）**：每個 Provider 都能選入口與出口（後端見架構 §7）。建立連線與「更換入口／出口」（原「更換伺服器」）兩個對話框都用 `RoutePicker`（`features/providers/route-picker.tsx`）：「出口」一個 `ServerPicker`（國家、城市、負載），下面是「入口」，依 `ROUTING`（`features/providers/model.ts`）：**Mullvad** 分段控制「與出口相同／另一台（多跳）」，選多跳時說明連線先到入口、再經 Mullvad 內部轉到出口、只走 IPv4，以及入口端的觀察者能從 port 看出出口；第二個 `ServerPicker` 選入口伺服器（不搶焦點），出口沒有確認的多跳埠時以 Callout 說明而且不能送出。**AirVPN** 是這台出口伺服器自己的入口清單（「位址 n · UDP port」與 IPv4／IPv6 位址，標「預設」「目前」），旁邊寫「AirVPN 沒有多跳：入口與出口是同一台伺服器（位址 n 即 AirVPN 的 Entry IP n）」。**一般設定**沒有供應商的伺服器清單：「更換入口／出口」停用，原因寫明入口與出口由 .conf 決定。兩個選擇下面的摘要卡寫「入口 … → 出口 …」與出口 IP 的說法（AirVPN 有清單的出口位址時寫出來，否則提示連線後以「檢查出口 IP」確認；多跳還沒選入口時寫「（選擇入口伺服器）」）。IP 版本的標籤改為「入口的 IP 版本」，多跳時只有 IPv4（提示「多跳只走 IPv4」），控制項不再被標籤撐寬。更換對話框的標題「更換「名稱」的入口與出口」，說明寫目前的路與「使用中的連線重新啟動後才會改走新的入口與出口」；入口與出口預設為目前的，兩者與 IP 版本都沒變時不能送出。WireGuard 設定的 inspector 分列「出口」「入口」（沒有另外的入口時寫「與出口相同」）；連線的出口檢查在 Mullvad 回報出口伺服器時寫出它，與設定的出口不同時提示。**總覽的流量路徑**：多跳的連線畫兩個節點「入口」（城市、伺服器名稱）與「出口」，說明文字變成「… → 加密 WireGuard tunnel → 入口 → 出口」；AirVPN 用非預設入口時，出口節點第二行是「位址 n · UDP port」，title 寫明入口與出口是同一台伺服器；沒有入口紀錄的舊連線與以前一樣。同時修正總覽流量圖在視窗縮小時不跟著變窄（格線的隱含欄是 `auto`，SVG 撐住寬度，ResizeObserver 收不到變窄；改為 `grid-cols-1`）。截圖檢視：dev stack 加上以真實 Mullvad relay 清單（10 國 360 台，多跳埠都確認過）與 AirVPN 狀態清單做成的列表，1920×1080 與 1512×982 的建立連線（Mullvad 多跳、AirVPN 非預設入口）、更換入口／出口（Mullvad 多跳、AirVPN）、WireGuard 設定 inspector 與總覽；過程中修正 AirVPN 說明在總覽被截斷、多跳節點截斷伺服器名稱、「入口 入口 n」的重複字、IP 版本標籤與摘要在多跳未選入口時的誤導。
- **DNS 設定失敗時中斷（2026-11-08）**：使用者被問到 NextDNS 連不到時怎麼辦，回答「中斷」（後端見架構 §4.1）。DNS 設定的「伺服器」區在伺服器清單下多一組選擇「伺服器全部失敗時」（`on_failure`，兩張選項卡，與代理埠協定相同的 `CHOICE_*` 配方）：「改用 WireGuard 設定的 DNS」——名稱照常解析，但這段時間改經 VPN 供應商的 DNS；「中斷，直到伺服器恢復」——這段時間連線的 App 無法解析名稱，不會改問其他 DNS（1512 寬時兩張卡各一行放得下）。預設是前者（之前存的設定也是）；伺服器區開頭的說明不再寫死備援；清單列與標頭的摘要在選了中斷時加上「失敗時中斷」；改這個選擇和其他 DNS 欄位一樣在儲存後提示使用中的連線要重新啟動（`workerInput.dns` 與 manager 的指紋都包含它）。**中斷的狀態**：連線的每個分頁開頭一個 danger Callout「DNS 已中斷：DNS 設定的伺服器都沒有回應」，寫明這份設定失敗時中斷、App 無法解析名稱而直接用 IP 的連線照常、伺服器恢復後自動恢復，並逐行列出各伺服器的原因與「檢查 DNS 設定」；證據的「DNS 探測」寫「中斷：…名稱無法解析」（tunnel 也失敗時列出失敗的原因）；連線清單與總覽的「需要處理」列出「DNS 已中斷：DNS 設定的伺服器都沒有回應，名稱無法解析，直到它們恢復」。
- **傳輸設定（2026-11-10）**：使用者要每條連線有更多可調的項目、多組現成的設定可選，並且能依狀況自動切換；被問到形式時選了「可共用的設定檔」（後端見架構 §4.5）。**頁面** `/transport`（導覽「政策」，DNS 設定之下；圖示 SlidersHorizontal）照「清單＋編輯器」配方（`features/transport/*`）：清單分「內建」與「我的設定」兩組（`MasterListHeading`），每列第二行是內容摘要（固定：「送 4 MiB／收 8 MiB」；自動：依往返時間由小到大以「→」串起各區間的設定名稱——設定名稱本身有「／」）與使用它的連線數；沒有選取時自動開啟「自動」（每條連線預設用它）。**內建設定**是程式的一部分：唯讀的 `PropertyGrid`（TCP 緩衝的起始與上限、往返 100 毫秒時單一連線的速度上限、TCP 行為與逾時、健康探測、使用中的連線；自動設定列出每個區間與連到那份設定的連結），footer 唯一的 primary 是「複製成我的設定」（`/transport/new?from=<代號>`，名稱預填「…的副本」）。**自訂設定**的編輯器：名稱、類型（`Segmented` 固定／自動）、固定時「TCP 緩衝」（送出與接收各有起始、上限，下方即時換算往返 100 毫秒時的速度上限，並說明嚴格隔離的連線由核心調整）與「TCP 行為、逾時與 UDP」（壅塞控制 `Segmented`、Nagle `Switch`、延遲 ACK、連線逾時、keepalive、無回應中止、UDP 緩衝），自動時「往返時間區間」（每列起點毫秒＋選一份固定設定，內建與我的設定分組；第一列固定 0 毫秒、不能移除；最多 6 列），兩者都有「健康探測」與「使用中的連線」。數字欄位用 `grid-cols-[repeat(auto-fit,minmax(11rem,1fr))]`，依 inspector 的寬度排成 3–5 欄：1512 與 1920 寬時整個編輯器不到 1.5 個可視高度，不需要分頁（原本兩欄時約 1.9 個）。範圍在送出前檢查（與伺服器相同的界限），起始大於上限、無回應中止小於 keepalive 的兩倍各有自己的訊息。**動作**（`actions.ts`、`action-host.tsx`）：自訂設定 footer「儲存」、⋯「複製、刪除」；仍有連線使用、或被自動設定的區間選用時「刪除」停用並寫出是誰；`?do=delete` 開同一個確認對話框。儲存後不提示重新啟動——傳輸設定立即套用到之後建立的連線——通知寫「使用它的連線之後建立的連線立即採用」。**連線**：編輯對話框在 DNS／安全設定之下多一個「傳輸設定」下拉（內建／我的設定分組，說明是那份設定的摘要）；「資源上限」的說明與「TCP 實際最多幾條」改依選用的設定計算（每條連線建立時預留的大小）。inspector「設定」分頁多一列「傳輸設定」：設定名稱（連到它），下面一行是 worker 回報的現況——自動時「目前套用「…」」、量到的往返時間、新連線的緩衝起始與上限、已放大的次數、因預算不足沒有放大的次數、嚴格隔離時沙箱的核心緩衝上限。系統的操作紀錄認得三個新操作（建立／修改／刪除傳輸設定）。截圖檢視（隔離的 headless Chrome，1920×1080 與 1512×982）：內建自動、內建固定、自訂固定、自訂自動、複製並顯示驗證錯誤、刪除確認、連線的設定分頁、連線的編輯對話框。
