// Text of the System page (系統): its tabs and header, the 狀態 view (the service's health, access, this installation,
// the metrics settings and the vault), the 能力 view, and the words several views share (what the manager owns, places
// an inspection could not look at). The other views have their own tables, split by sub-area:
// diagnostics/messages.tsx (診斷 and 執行環境), recovery/messages.tsx (恢復) and operations/messages.ts (操作紀錄).
// The page's title is the section name (components/shell/messages.ts, `nav.system`). Reasons, findings and errors the
// service returns are shown as they arrive. A .tsx: a sentence carries markup (src/i18n/README.md).

import type { ReactNode } from "react";
import type { CapabilityState } from "@/api/types";
import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

export const m = defineMessages({
  en: {
    /** The page's tabs (`?view=`). */
    views: {
      overview: "Status",
      capabilities: "Capabilities",
      diagnostics: "Diagnostics",
      runtime: "Runtime",
      recovery: "Recovery",
      operations: "Operation log",
    },
    page: {
      description:
        "Whether the service is healthy, this host's capabilities, the diagnostics report, recovery of leftover resources, and recent operations.",
      help: "Status: the verdict on the core service, live updates, the databases and key storage, the addresses to open and this installation. Capabilities: the protection this host can provide. Diagnostics and Runtime: checks derived from the actual state, owned resources, databases, processes, disk and program versions, downloadable as JSON (without secrets, connection destinations or account numbers). Recovery: handles only what can be proven to belong to this VPN Manager and to be stale; before every cleanup it lists the exact items for you to confirm, and cleaning up never starts a connection. Operation log: recent requests such as creating, changing, starting and stopping, and their results.",
      helpText:
        "The diagnostics report holds no secrets; recovery cleans up only items proven to belong to this VPN Manager and to be stale, and asks first.",
      /** A view whose code is still loading. */
      loading: "Loading",
    },
    /** Machine values in one line (addresses, networks, ports, names). */
    list: (items: readonly string[]) => items.join(", "),
    version: "Version",
    build: "Build",
    installationId: "Installation ID",
    dataDir: "Data directory",
    /** What the copy button next to the data directory copies. */
    copyDataDir: "data directory",
    /** `time`: when a process started, as a date and time. */
    startedAt: (time: string) => `Started ${time}`,
    /** A place an inspection could not look at, and why (the service's words). */
    gap: (what: string, path: string | null, reason: string) => `${what}${path ? ` (${path})` : ""}: ${reason}`,
    /** What the manager holds now (診斷 and 恢復 list it). */
    owned: {
      title: "Owned resources",
      /** Connection worker processes. */
      workers: "Workers",
      /** The sockets connections' connectors listen on. */
      connectors: "Connector sockets",
      managedApps: "Managed apps",
      gateways: "Gateways",
      keyLocks: "Key locks",
      sandboxes: "Strict isolation sandboxes",
      noWorkers: "No worker running",
      noGateways: "No Gateways held",
      /** Connections that did not answer in time, by name: the Gateways they hold are missing from the list. */
      unanswered: (names: readonly string[]) =>
        `${listEn.format(names)} did not answer in time: the Gateways ${names.length === 1 ? "it holds are" : "they hold are"} not listed`,
      notChecked: "Could not check",
    },
    /** The 狀態 view's raised summary: the service path and the Store. */
    health: {
      label: "Service health",
      /** `when`: relative ("3 seconds ago"). */
      observed: (when: string) => `Observed ${when}`,
      manager: "Core service",
      connected: "Connected",
      disconnected: "Not connected",
      stream: "Live updates",
      live: "Live",
      connecting: "Connecting",
      interrupted: "Interrupted",
      events: "Event stream",
      polling: "Polling every 20 seconds instead",
      controlDb: "Control database",
      controlDbDetail: "Settings and connection state",
      metricsDb: "Metrics database",
      metricsDbDetail: "Traffic and performance samples",
      writable: "Writable",
      notWritable: "Not writable",
      keystore: "Key storage",
      keystoreDetail: "Kept by VPN Manager itself",
    },
    /** The 狀態 view's conclusion, worst first. */
    verdict: {
      reading: "Reading",
      readingDetail: "Reading the service state.",
      controlDown: "The control database cannot be written",
      controlDownDetail:
        "Adding, changing and deleting all fail; connections already running are not affected. See “Diagnostics”.",
      metricsDown: "The metrics database cannot be written",
      metricsDownDetail: "Connections are not affected, but the charts will have gaps. See “Diagnostics”.",
      /** `state`: the key storage's capability state in words (Restricted, Degraded …). */
      keystore: (state: string) => `Key storage: ${state}`,
      keystoreDetail: "Adding accounts or keys may fail. See “Diagnostics”.",
      fine: "All is well",
      fineDetail: "The core service is connected, the databases can be written, and the state updates live.",
    },
    lan: {
      title: "The management interface is open to the local network",
      /** `networks`: the allowed networks, listed. */
      body: (networks: string) =>
        `Any device in the allowed networks (${networks}) can operate VPN Manager without signing in, including starting managed apps. Connections on this host still accept only your own programs. To take that back, run vpn-installer upgrade --listen-address 127.0.0.1.`,
    },
    loadingAccess: "Loading access and installation",
    access: {
      title: "Access",
      lanDescription: "Devices in the allowed networks can open these addresses directly",
      hostOnly: "Only this host can open it",
      addresses: "Addresses",
      noAddress: "This host has no address other devices can reach.",
      listening: "Listening on",
      allowed: "Allowed networks",
      allowedHint: "Other sources are refused and logged before they can read anything",
      change: "Set at installation; to change it, run:",
      /** The placeholders of the commands that change it: `vpn-installer upgrade --port <port>`. */
      port: "port",
      address: "address",
      network: "network",
    },
    installation: {
      title: "This installation",
      os: "Operating system",
      idUnknown: "Unknown (the core service is not connected)",
      afterRestart: "After a restart",
      afterRestartValue:
        "Connections that were running resume by themselves; connections you stopped or emergency stopped stay stopped",
      dataDirHint: "Programs, data, the vault key and logs (logs/) are all here",
    },
    settings: {
      title: "Metrics settings",
      description: "How long the samples behind the charts are kept, and how much space they may take.",
      loading: "Loading metrics settings",
      retention: "Raw metrics retention (hours)",
      retentionHint: "At most 168 hours (7 days); after that, per-minute and hourly summaries are used",
      retentionRange: "1–168 hours",
      quota: "Metrics space limit (MiB)",
      quotaHint: "Above it, the oldest data is deleted first and the charts mark a gap",
      fixFields: "Some fields need fixing",
      noChanges: "No changes",
      saved: "Settings saved",
      dirty: "There are unsaved changes",
      current: "These are the current settings",
      save: "Save settings",
    },
    vault: {
      title: "Key vault",
      note: "Only metadata is listed; private keys are stored encrypted, and no interface can read them back or export them.",
      /** The vault's description while it holds keys: how many, then the note. */
      count: (count: number, note: string) => `${count} ${count === 1 ? "key" : "keys"}. ${note}`,
      keys: "Keys",
      loading: "Loading keys",
      empty: "The vault is empty",
      emptyBody: "Once you add a WireGuard profile or a provider account, its private key is kept here.",
      /** `when`: relative ("3 days ago"). */
      created: (when: string) => `Created ${when}`,
      /** After a key's kind: its public fingerprint (shortened, as an element). */
      fingerprint: (value: ReactNode): ReactNode => (
        <>
          {" · fingerprint "}
          {value}
        </>
      ),
      kind: {
        wireguard_private_key: "WireGuard private key",
        wireguard_preshared_key: "WireGuard preshared key",
        provider_credential: "Provider account credentials",
      },
    },
    capabilities: {
      title: "This host's capabilities",
      description: "The protection this host can provide now",
      loading: "Loading host capabilities",
      state: {
        supported: "Supported",
        unsupported: "Unsupported",
        unverified: "Unverified",
        blocked: "Restricted",
        degraded: "Degraded",
      },
      group: {
        connections: "Connections and Gateways",
        apps: "Managed apps",
        forwards: "Port forwards",
        keys: "Keys",
        other: "Other",
      },
      /** Each name reads within its group. */
      name: {
        explicit_proxy: "Explicit proxy (SOCKS5/HTTP)",
        ipv6_tunnel: "IPv6 through the tunnel",
        network_rate_limit: "Bandwidth limit",
        strict_netns: "Connections with strict isolation (Linux sandbox)",
        app_proxy_env: "Proxy environment variables",
        app_enforced_proxy: "Enforced proxy (macOS Seatbelt)",
        app_strict_netns: "Strict isolation (Linux netns)",
        managed_process_network: "System-level network isolation",
        limit_memory: "Memory limit",
        limit_cpu: "CPU limit",
        limit_processes: "Process limit",
        limit_open_files: "Open file limit",
        forwarded_app_endpoint: "Forwarding to a managed app",
        forward_reservation: "Inbound port reserved at the provider",
        secret_keystore: "Key storage",
      },
      /** How many capabilities are in each state; the states with none are left out. */
      summary: (n: Record<CapabilityState, number>) =>
        [
          `${n.supported} available`,
          n.degraded ? `${n.degraded} degraded` : null,
          n.blocked ? `${n.blocked} restricted` : null,
          n.unverified ? `${n.unverified} unverified` : null,
          n.unsupported ? `${n.unsupported} not supported on this host` : null,
        ]
          .filter(Boolean)
          .join(" · "),
    },
  },
  "zh-TW": {
    views: {
      overview: "狀態",
      capabilities: "能力",
      diagnostics: "診斷",
      runtime: "執行環境",
      recovery: "恢復",
      operations: "操作紀錄",
    },
    page: {
      description: "服務是否健康、這台主機的能力、診斷報告、遺留資源的恢復，以及最近的操作。",
      help: "狀態：核心服務、即時更新、資料庫與金鑰保管的結論，存取網址與這個安裝。能力：這台主機能提供的保護。診斷與執行環境：從實際狀態推得的檢查、擁有的資源、資料庫、程序、磁碟與程式版本，可下載成 JSON（不含秘密、連線目的地與帳號號碼）。恢復：只處理能證明屬於這個 VPN Manager、而且已經失效的東西，每次清理前都會列出確切的項目請你確認，清理不會啟動任何連線。操作紀錄：最近的建立、修改、啟停等請求與它們的結果。",
      helpText: "診斷報告不含秘密；恢復只清理能證明屬於這個 VPN Manager 且已失效的項目，並先確認。",
      loading: "載入中",
    },
    list: (items) => items.join("、"),
    version: "版本",
    build: "Build",
    installationId: "安裝識別碼",
    dataDir: "資料目錄",
    copyDataDir: "資料目錄",
    startedAt: (time) => `啟動於 ${time}`,
    gap: (what, path, reason) => `${what}${path ? `（${path}）` : ""}：${reason}`,
    owned: {
      title: "擁有的資源",
      workers: "worker",
      connectors: "connector",
      managedApps: "受管 App",
      gateways: "代理埠",
      keyLocks: "金鑰鎖",
      sandboxes: "嚴格隔離 sandbox",
      noWorkers: "沒有執行中的 worker",
      noGateways: "沒有持有的代理埠",
      unanswered: (names) => `${names.join("、")} 沒有及時回應：它們持有的代理埠沒有列出`,
      notChecked: "無法檢查",
    },
    health: {
      label: "服務健康",
      observed: (when) => `${when}觀測`,
      manager: "核心服務",
      connected: "已連線",
      disconnected: "未連線",
      stream: "即時更新",
      live: "即時",
      connecting: "連線中",
      interrupted: "已中斷",
      events: "事件串流",
      polling: "改為每 20 秒輪詢",
      controlDb: "控制資料庫",
      controlDbDetail: "設定與連線狀態",
      metricsDb: "指標資料庫",
      metricsDbDetail: "流量與效能樣本",
      writable: "可寫入",
      notWritable: "無法寫入",
      keystore: "金鑰保管",
      keystoreDetail: "VPN Manager 自己保管",
    },
    verdict: {
      reading: "讀取中",
      readingDetail: "正在讀取服務狀態。",
      controlDown: "控制資料庫無法寫入",
      controlDownDetail: "新增、修改與刪除都會失敗；已在執行的連線不受影響。見「診斷」。",
      metricsDown: "指標資料庫無法寫入",
      metricsDownDetail: "連線不受影響，但圖表會出現缺口。見「診斷」。",
      keystore: (state) => `金鑰保管${state}`,
      keystoreDetail: "新增帳號或金鑰可能失敗。見「診斷」。",
      fine: "一切正常",
      fineDetail: "核心服務已連線、資料庫可以寫入，狀態即時更新。",
    },
    lan: {
      title: "管理介面開放給區網",
      body: (networks) =>
        `允許的網段（${networks}）裡的任何裝置，不需登入就能操作 VPN Manager，包括啟動受管 App。這台主機上的連線仍只接受你自己的程式。要收回請執行 vpn-installer upgrade --listen-address 127.0.0.1。`,
    },
    loadingAccess: "載入存取與安裝",
    access: {
      title: "存取",
      lanDescription: "允許的網段裡的裝置可以直接開啟這些網址",
      hostOnly: "只有這台主機可以開啟",
      addresses: "網址",
      noAddress: "這台主機沒有其他裝置能連到的位址。",
      listening: "監聽",
      allowed: "允許的網段",
      allowedHint: "其他來源在讀取任何資料前就被拒絕並記錄",
      change: "安裝時決定；要更換請執行：",
      port: "埠",
      address: "位址",
      network: "網段",
    },
    installation: {
      title: "這個安裝",
      os: "作業系統",
      idUnknown: "未知（核心服務未連線）",
      afterRestart: "重新啟動後",
      afterRestartValue: "原本在執行的連線自動恢復；你停止或急停的連線維持停止",
      dataDirHint: "程式、資料、保險庫金鑰與日誌（logs/）都在這裡",
    },
    settings: {
      title: "指標設定",
      description: "圖表用的樣本保留多久、最多占多少空間。",
      loading: "載入指標設定",
      retention: "原始指標保留（小時）",
      retentionHint: "最多 168 小時（7 天）；之後改用每分鐘與每小時的彙總",
      retentionRange: "1–168 小時",
      quota: "指標空間上限（MiB）",
      quotaHint: "超過時從最舊的資料先刪，圖表記為缺口",
      fixFields: "有欄位需要修正",
      noChanges: "沒有變更",
      saved: "已儲存設定",
      dirty: "有尚未儲存的變更",
      current: "已是目前的設定",
      save: "儲存設定",
    },
    vault: {
      title: "金鑰保管庫",
      note: "只列中繼資料，私鑰加密保存，任何介面都無法讀回或匯出。",
      count: (count, note) => `${count} 把金鑰；${note}`,
      keys: "金鑰",
      loading: "載入金鑰",
      empty: "保管庫是空的",
      emptyBody: "加入 WireGuard 設定或供應商帳號後，私鑰會保存在這裡。",
      created: (when) => `${when}建立`,
      fingerprint: (value) => (
        <>
          {" · 指紋 "}
          {value}
        </>
      ),
      kind: {
        wireguard_private_key: "WireGuard 私鑰",
        wireguard_preshared_key: "WireGuard 預共用金鑰",
        provider_credential: "供應商帳號憑證",
      },
    },
    capabilities: {
      title: "這台主機的能力",
      description: "這台主機目前能提供的保護",
      loading: "載入主機能力",
      state: {
        supported: "支援",
        unsupported: "不支援",
        unverified: "未驗證",
        blocked: "受限",
        degraded: "降級",
      },
      group: {
        connections: "連線與代理埠",
        apps: "受管 App",
        forwards: "轉發",
        keys: "金鑰",
        other: "其他",
      },
      name: {
        explicit_proxy: "明確代理（SOCKS5／HTTP）",
        ipv6_tunnel: "IPv6 經 tunnel",
        network_rate_limit: "頻寬限制",
        strict_netns: "嚴格隔離的連線（Linux 沙箱）",
        app_proxy_env: "代理環境變數",
        app_enforced_proxy: "強制代理（macOS Seatbelt）",
        app_strict_netns: "嚴格隔離（Linux netns）",
        managed_process_network: "系統層網路隔離",
        limit_memory: "記憶體上限",
        limit_cpu: "CPU 上限",
        limit_processes: "程序數上限",
        limit_open_files: "開啟檔案上限",
        forwarded_app_endpoint: "轉發到受管 App",
        forward_reservation: "供應商端保留連入埠",
        secret_keystore: "金鑰保管",
      },
      /** 「11 項可用・1 項降級・2 項這台主機不支援」 */
      summary: (n) =>
        [
          `${n.supported} 項可用`,
          n.degraded ? `${n.degraded} 項降級` : null,
          n.blocked ? `${n.blocked} 項受限` : null,
          n.unverified ? `${n.unverified} 項未驗證` : null,
          n.unsupported ? `${n.unsupported} 項這台主機不支援` : null,
        ]
          .filter(Boolean)
          .join("・"),
    },
  },
  ja: {
    views: {
      overview: "状態",
      capabilities: "機能",
      diagnostics: "診断",
      runtime: "実行環境",
      recovery: "復旧",
      operations: "操作履歴",
    },
    page: {
      description: "サービスが正常かどうか、このホストの機能、診断レポート、残留リソースの復旧、最近の操作。",
      help: "状態：コアサービス、リアルタイム更新、データベース、鍵の保管についての結論と、アクセス用のアドレス、このインストール。機能：このホストが提供できる保護。診断と実行環境：実際の状態から導いたチェック、保有リソース、データベース、プロセス、ディスク、プログラムのバージョン。JSON としてダウンロードできます（秘密情報、接続先、アカウント番号は含みません）。復旧：この VPN Manager のもので、すでに無効だと証明できるものだけを扱います。クリーンアップの前には毎回、対象の項目を正確に示して確認を求め、クリーンアップで接続が開始されることはありません。操作履歴：最近の作成、変更、開始・停止などのリクエストとその結果。",
      helpText:
        "診断レポートに秘密情報は含まれません。復旧では、この VPN Manager のもので無効だと証明できる項目だけを、確認してからクリーンアップします。",
      loading: "読み込み中",
    },
    list: (items) => items.join("、"),
    version: "バージョン",
    build: "ビルド",
    installationId: "インストール ID",
    dataDir: "データディレクトリ",
    copyDataDir: "データディレクトリ",
    startedAt: (time) => `${time} に起動`,
    gap: (what, path, reason) => `${what}${path ? `（${path}）` : ""}：${reason}`,
    owned: {
      title: "保有リソース",
      workers: "worker",
      connectors: "connector",
      managedApps: "管理対象アプリ",
      gateways: "ゲートウェイ",
      keyLocks: "鍵のロック",
      sandboxes: "厳格な分離のサンドボックス",
      noWorkers: "実行中の worker はありません",
      noGateways: "保持しているゲートウェイはありません",
      unanswered: (names) =>
        `${names.join("、")} は時間内に応答しませんでした。保持しているゲートウェイは一覧にありません`,
      notChecked: "チェック不可",
    },
    health: {
      label: "サービスの健全性",
      observed: (when) => `観測：${when}`,
      manager: "コアサービス",
      connected: "接続済み",
      disconnected: "未接続",
      stream: "リアルタイム更新",
      live: "リアルタイム",
      connecting: "接続中",
      interrupted: "切断",
      events: "イベントストリーム",
      polling: "20 秒ごとの取得に切り替え中",
      controlDb: "制御データベース",
      controlDbDetail: "設定と接続の状態",
      metricsDb: "メトリクスデータベース",
      metricsDbDetail: "トラフィックとパフォーマンスのサンプル",
      writable: "書き込み可",
      notWritable: "書き込み不可",
      keystore: "鍵の保管",
      keystoreDetail: "VPN Manager 自身が保管",
    },
    verdict: {
      reading: "読み込み中",
      readingDetail: "サービスの状態を読み込んでいます。",
      controlDown: "制御データベースに書き込めません",
      controlDownDetail:
        "追加、変更、削除はすべて失敗します。実行中の接続には影響しません。「診断」を参照してください。",
      metricsDown: "メトリクスデータベースに書き込めません",
      metricsDownDetail: "接続には影響しませんが、グラフに欠落が生じます。「診断」を参照してください。",
      keystore: (state) => `鍵の保管：${state}`,
      keystoreDetail: "アカウントや鍵の追加に失敗する可能性があります。「診断」を参照してください。",
      fine: "すべて正常",
      fineDetail: "コアサービスに接続済みで、データベースに書き込めます。状態はリアルタイムで更新されます。",
    },
    lan: {
      title: "管理画面がローカルネットワークに公開されています",
      body: (networks) =>
        `許可されたネットワーク（${networks}）内のどのデバイスも、ログインせずに VPN Manager を操作できます。管理対象アプリの開始も含みます。このホスト上の接続は、引き続き自分のプログラムだけを受け付けます。元に戻すには vpn-installer upgrade --listen-address 127.0.0.1 を実行してください。`,
    },
    loadingAccess: "アクセスとインストールを読み込み中",
    access: {
      title: "アクセス",
      lanDescription: "許可されたネットワーク内のデバイスは、これらのアドレスを直接開けます",
      hostOnly: "このホストからのみ開けます",
      addresses: "アドレス",
      noAddress: "このホストには、ほかのデバイスから接続できるアドレスがありません。",
      listening: "待ち受け",
      allowed: "許可されたネットワーク",
      allowedHint: "それ以外の送信元は、データを読み取る前に拒否され、記録されます",
      change: "インストール時に決まります。変更するには次を実行してください：",
      port: "ポート",
      address: "アドレス",
      network: "ネットワーク",
    },
    installation: {
      title: "このインストール",
      os: "OS",
      idUnknown: "不明（コアサービスに未接続）",
      afterRestart: "再起動後",
      afterRestartValue: "実行中だった接続は自動的に再開し、停止または緊急停止した接続は停止したままです",
      dataDirHint: "プログラム、データ、保管庫の鍵、ログ（logs/）はすべてここにあります",
    },
    settings: {
      title: "メトリクス設定",
      description: "グラフに使うサンプルの保持期間と、使える容量の上限。",
      loading: "メトリクス設定を読み込み中",
      retention: "生のメトリクスの保持期間（時間）",
      retentionHint: "最大 168 時間（7 日）。それ以降は 1 分ごとと 1 時間ごとの集計を使います",
      retentionRange: "1–168 時間",
      quota: "メトリクスの容量上限（MiB）",
      quotaHint: "超えると最も古いデータから削除され、グラフには欠落として記録されます",
      fixFields: "修正が必要な項目があります",
      noChanges: "変更はありません",
      saved: "設定を保存しました",
      dirty: "保存していない変更があります",
      current: "現在の設定です",
      save: "設定を保存",
    },
    vault: {
      title: "鍵保管庫",
      note: "メタデータのみを表示します。秘密鍵は暗号化して保存され、どのインターフェースからも読み戻したりエクスポートしたりできません。",
      count: (count, note) => `${count} 個の鍵。${note}`,
      keys: "鍵",
      loading: "鍵を読み込み中",
      empty: "保管庫は空です",
      emptyBody: "WireGuard 設定またはプロバイダーアカウントを追加すると、秘密鍵がここに保存されます。",
      created: (when) => `作成：${when}`,
      fingerprint: (value) => (
        <>
          {" · フィンガープリント "}
          {value}
        </>
      ),
      kind: {
        wireguard_private_key: "WireGuard 秘密鍵",
        wireguard_preshared_key: "WireGuard 事前共有鍵",
        provider_credential: "プロバイダーアカウントの認証情報",
      },
    },
    capabilities: {
      title: "このホストの機能",
      description: "このホストが現在提供できる保護",
      loading: "ホストの機能を読み込み中",
      state: {
        supported: "対応",
        unsupported: "非対応",
        unverified: "未検証",
        blocked: "制限あり",
        degraded: "機能低下",
      },
      group: {
        connections: "接続とゲートウェイ",
        apps: "管理対象アプリ",
        forwards: "ポート転送",
        keys: "鍵",
        other: "その他",
      },
      name: {
        explicit_proxy: "明示的プロキシ（SOCKS5／HTTP）",
        ipv6_tunnel: "トンネル経由の IPv6",
        network_rate_limit: "帯域制限",
        strict_netns: "厳格な分離の接続（Linux サンドボックス）",
        app_proxy_env: "プロキシ環境変数",
        app_enforced_proxy: "強制プロキシ（macOS Seatbelt）",
        app_strict_netns: "厳格な分離（Linux netns）",
        managed_process_network: "システムレベルのネットワーク分離",
        limit_memory: "メモリ上限",
        limit_cpu: "CPU 上限",
        limit_processes: "プロセス数の上限",
        limit_open_files: "オープンファイル数の上限",
        forwarded_app_endpoint: "管理対象アプリへの転送",
        forward_reservation: "プロバイダー側での着信ポートの予約",
        secret_keystore: "鍵の保管",
      },
      summary: (n) =>
        [
          `${n.supported} 件が利用可能`,
          n.degraded ? `${n.degraded} 件が機能低下` : null,
          n.blocked ? `${n.blocked} 件が制限あり` : null,
          n.unverified ? `${n.unverified} 件が未検証` : null,
          n.unsupported ? `${n.unsupported} 件はこのホストでは非対応` : null,
        ]
          .filter(Boolean)
          .join("・"),
    },
  },
});
