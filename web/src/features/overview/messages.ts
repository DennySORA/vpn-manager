// Text of the Overview page (總覽): the summary figures, the setup steps, what needs attention, the traffic path
// (topology.tsx) and the traffic chart under it (traffic-chart.tsx). 連線 is a connection (an Instance); the SSH
// downloads, the SSH proxy and the App sandbox are the parts of a connection's traffic, named as the top bar's traffic
// strip names them.

import { defineMessages, intlLocale } from "@/i18n";

const integer = new Intl.NumberFormat(intlLocale);

function gatewaysEn(count: number): string {
  return count === 1 ? "Gateway" : "Gateways";
}

export const m = defineMessages({
  en: {
    page: {
      description: "Which traffic is protected, where it leaves, and what needs your attention.",
      help: "“Protected” counts the connections that are connected and whose traffic leaves only through the tunnel. Download and upload are the totals of the last second over every running connection: the traffic of Gateways and port forwards, plus that of the App sandbox in strictly isolated connections (with strict isolation, port forwards count toward the App sandbox). The traffic path flows only while a connection is ready and carries traffic, and it can be paused.",
      helpText:
        "“Protected” counts the connections that are connected and whose traffic leaves only through the tunnel.",
      importProfile: "Import profile",
      addConnection: "Add connection",
    },
    summary: {
      label: "Summary",
      loading: "Loading the summary",
      protected: "Protected connections",
      /** Under the protected connections. */
      noConnection: "No connection created yet",
      tunnelOnly: "Traffic leaves only through the tunnel",
      noReady: "No exit is connected",
      reading: "Reading the state",
      managerDown: "Core service not connected",
      /** Under download and upload. */
      allConnections: "All connections combined",
      /** The App sandboxes' part of download or upload, under it. */
      sandboxShare: (rate: string) => `Including App sandbox ${rate}`,
      /** Under the count of what needs attention. */
      serving: (count: number) => `${count} ${gatewaysEn(count)} serving`,
    },
    onboarding: {
      title: "Getting started",
      intro: "Four steps to make applications' traffic leave only through a WireGuard exit.",
      /** After a step's title, for assistive technology. */
      done: " (done)",
      notDone: " (not done yet)",
      profile: {
        title: "Get a WireGuard profile",
        addAccount: "Add provider account",
        importConf: "Import .conf",
        body: "Import the .conf your provider gives you, or add a Mullvad or AirVPN account and pick a server directly; the private key is only stored encrypted and cannot be read back.",
      },
      connection: {
        title: "Create a connection",
        body: "A connection is an independent exit; you can have several at once.",
      },
      gateway: {
        title: "Create a local Gateway",
        body: "Applications use a connection through a SOCKS5 or HTTP Gateway on 127.0.0.1.",
      },
      verify: {
        title: "Start it and pass verification",
        go: "Go",
        body: "Connections open only after both the handshake and the DNS probe pass.",
      },
    },
    attention: {
      title: "Needs attention",
      items: "Items that need attention",
      none: "Nothing needs attention right now.",
    },
    /** What needs attention besides the connections. */
    system: {
      storeTitle: "Storage",
      storeText: "The database cannot be written: new changes may not be saved.",
      clockTitle: "Host clock",
      /** `skew`: how far the host's clock is off, when that is known and large enough to say. */
      clockText: (skew: string | null) =>
        `The host clock is not synchronized${skew !== null ? ` (${skew})` : ""}: turn on time synchronization (NTP) on the host. Metrics and logs are stamped with the host's clock.`,
    },
    path: {
      title: "Traffic path",
      emptyTitle: "No traffic path yet",
      emptyBody: "Once the first connection is created, the path of each flow of traffic shows here.",
      pause: "Pause animation",
      lanes: "Traffic path of each connection",
      /** The first kind of source of a connection's traffic. */
      ports: "Local Gateways",
      /** `sources`: the kinds of sources, as a list; `relay`: a connection enters at another server than its exit. */
      legend: (sources: string, relay: boolean) =>
        `${sources} → connection → encrypted WireGuard tunnel → ${relay ? "entry → exit" : "exit"}`,
    },
    /** A source of a connection's traffic: its accessible name with its live rates. */
    node: (title: string, download: string, upload: string) => `${title}, download ${download}, upload ${upload}`,
    port: {
      /** `kind`: the Gateway's protocol. */
      title: (name: string, port: number, kind: string, failed: boolean, enabled: boolean) =>
        `Gateway ${name}, 127.0.0.1:${port}, ${kind}${failed ? ", cannot be enabled" : ""}${enabled ? "" : ", disabled"}: ordinary proxy traffic (without SSH)`,
    },
    pull: {
      label: "SSH downloads",
      count: (active: number, total: number) => `${active}/${total} ${total === 1 ? "job" : "jobs"}`,
      title: (total: number, active: number) =>
        `SSH downloads: ${total} ${total === 1 ? "job goes" : "jobs go"} through this connection's Gateways, ${active} in progress (connecting, listing or downloading)`,
    },
    proxy: {
      label: "SSH proxy",
      /** `sessions`: SSH connections open now (null: no live data). */
      title: (sessions: number | null) =>
        `SSH proxy: SSH connections open through this connection's Gateways (vpnctl ssh-proxy, and connections to port 22)${sessions === null ? ", no live data" : `, ${sessions} now`}`,
      sessions: (count: number) => `${integer.format(count)} ${count === 1 ? "connection" : "connections"}`,
    },
    sandbox: {
      label: "App sandbox",
      /** `names`: the strict apps of the connection; `running`: how many of them run. */
      title: (names: readonly string[], running: number) =>
        `App sandbox: ${names.join(", ")} (${running ? (names.length > 1 ? `${running} running` : "running") : "not running"})`,
    },
    lane: {
      noGateways: "No Gateways",
      generation: (generation: number) => `generation ${generation}`,
    },
    exit: {
      /** A multihop route's accessible name. */
      route: (entry: string, exit: string) => `Entry ${entry} → exit ${exit}`,
      entryTitle: (server: string) => `Entry ${server}`,
      entry: "Entry",
      exit: "Exit",
      noPlace: "Location not given",
      sameServer: (address: string) => `${address}: the entry and the exit are the same server`,
    },
    chart: {
      title: "Traffic",
      range: "Time range of the traffic chart",
      tableLabel: "Traffic: table",
      table: "Table",
      /** `range`: the chosen range, in words. */
      scope: (range: string) => `Payload of every connection, bit/s · ${range}`,
      /** A part's share of the range, after the scope. */
      share: (label: string, percent: string) => `${label}: ${percent}`,
      viewInMetrics: "View in Metrics",
      stale: "Cannot update: showing the previous data",
      noLiveSample: "No live sample",
      sandboxPart: (rate: string) => `Of which App sandbox ${rate}`,
      gaps: (reasons: readonly string[]) => `Gaps: ${reasons.join(", ")}`,
      livePending: "Live sample, not stored yet",
      /** `direction`: download or upload. */
      plotLabel: (direction: string, range: string) =>
        `${direction} (payload of every connection, with its SSH downloads and SSH proxy parts, bit/s, ${range}); use the left and right arrow keys to read the values point by point, or open the table`,
      empty: (range: string) => `No traffic data (${range})`,
      loadFailed: "Cannot load the traffic data",
      loading: "Loading the traffic data",
    },
  },
  "zh-TW": {
    page: {
      description: "哪些流量正受保護、經哪裡送出，以及需要你處理的事。",
      help: "「受保護」是已連線、而且流量只經 tunnel 送出的連線；下載與上傳是所有執行中連線最近一秒的合計：代理埠與轉發的流量，加上嚴格隔離的連線裡 App 沙箱的流量（嚴格隔離時轉發也算在 App 沙箱裡）。流量路徑只在連線就緒且有流量時流動，可以暫停。",
      helpText: "「受保護」是已連線、而且流量只經 tunnel 送出的連線。",
      importProfile: "匯入設定",
      addConnection: "新增連線",
    },
    summary: {
      label: "摘要",
      loading: "載入摘要",
      protected: "受保護的連線",
      noConnection: "尚未建立連線",
      tunnelOnly: "流量只經 tunnel 送出",
      noReady: "沒有已連線的出口",
      reading: "正在讀取狀態",
      managerDown: "核心服務未連線",
      allConnections: "所有連線合計",
      sandboxShare: (rate) => `含 App 沙箱 ${rate}`,
      serving: (count) => `${count} 個代理埠服務中`,
    },
    onboarding: {
      title: "開始使用",
      intro: "四個步驟讓應用程式的流量只經 WireGuard 出口送出。",
      done: "（已完成）",
      notDone: "（尚未完成）",
      profile: {
        title: "取得 WireGuard 設定",
        addAccount: "加入供應商帳號",
        importConf: "匯入 .conf",
        body: "匯入供應商提供的 .conf，或加入 Mullvad／AirVPN 帳號直接挑選伺服器建立；私鑰只會加密保存，無法讀回。",
      },
      connection: {
        title: "建立連線",
        body: "一條連線就是一個獨立的出口，可同時有多條。",
      },
      gateway: {
        title: "建立本機代理埠",
        body: "應用程式透過 127.0.0.1 上的 SOCKS5 或 HTTP 代理埠使用連線。",
      },
      verify: {
        title: "啟動並通過驗證",
        go: "前往",
        body: "握手與 DNS 探測都通過後才會開放連線。",
      },
    },
    attention: {
      title: "需要處理",
      items: "需要處理的項目",
      none: "目前沒有需要處理的項目。",
    },
    system: {
      storeTitle: "儲存",
      storeText: "資料庫無法寫入：新的變更可能無法保存。",
      clockTitle: "主機時間",
      clockText: (skew) =>
        `主機時間沒有同步${skew !== null ? `（${skew}）` : ""}：請在主機啟用時間同步（NTP）。數據與紀錄的時間照主機的時鐘。`,
    },
    path: {
      title: "流量路徑",
      emptyTitle: "還沒有流量路徑",
      emptyBody: "建立第一條連線後，這裡會顯示每條流量的路徑。",
      pause: "暫停動畫",
      lanes: "每條連線的流量路徑",
      ports: "本機代理埠",
      legend: (sources, relay) => `${sources} → 連線 → 加密 WireGuard tunnel → ${relay ? "入口 → 出口" : "出口"}`,
    },
    node: (title, download, upload) => `${title}，下載 ${download}、上傳 ${upload}`,
    port: {
      title: (name, port, kind, failed, enabled) =>
        `代理埠 ${name}，127.0.0.1:${port}，${kind}${failed ? "，無法啟用" : ""}${enabled ? "" : "，已停用"}：一般代理流量（不含 SSH）`,
    },
    pull: {
      label: "SSH 下載",
      count: (active, total) => `${active}／${total} 個工作`,
      title: (total, active) => `SSH 下載：${total} 個工作經這條連線的代理埠，${active} 個進行中（連線、列出或下載中）`,
    },
    proxy: {
      label: "SSH 代理",
      title: (sessions) =>
        `SSH 代理：經這條連線的代理埠開著的 SSH 連線（vpnctl ssh-proxy，以及到 22 埠的連線）${sessions === null ? "，沒有即時數據" : `，目前 ${sessions} 條`}`,
      sessions: (count) => `${integer.format(count)} 條連線`,
    },
    sandbox: {
      label: "App 沙箱",
      title: (names, running) =>
        `App 沙箱：${names.join("、")}（${running ? (names.length > 1 ? `${running} 個執行中` : "執行中") : "未執行"}）`,
    },
    lane: {
      noGateways: "沒有代理埠",
      generation: (generation) => `第 ${generation} 代`,
    },
    exit: {
      route: (entry, exit) => `入口 ${entry} → 出口 ${exit}`,
      entryTitle: (server) => `入口 ${server}`,
      entry: "入口",
      exit: "出口",
      noPlace: "未標示位置",
      sameServer: (address) => `${address}：入口與出口是同一台伺服器`,
    },
    chart: {
      title: "流量",
      range: "流量圖的時間範圍",
      tableLabel: "流量：表格",
      table: "表格",
      scope: (range) => `所有連線的 payload，bit/s · ${range}`,
      share: (label, percent) => `${label}占 ${percent}`,
      viewInMetrics: "在數據統計查看",
      stale: "無法更新：顯示的是上一次的資料",
      noLiveSample: "沒有即時樣本",
      sandboxPart: (rate) => `其中 App 沙箱 ${rate}`,
      gaps: (reasons) => `缺口：${reasons.join("、")}`,
      livePending: "即時樣本，尚未存入",
      plotLabel: (direction, range) =>
        `${direction}（所有連線的 payload，與其中的 SSH 下載、SSH 代理，bit/s，${range}）；用左右鍵逐點查看數值，或開啟表格`,
      empty: (range) => `${range}沒有流量資料`,
      loadFailed: "無法取得流量資料",
      loading: "正在讀取流量資料",
    },
  },
  ja: {
    page: {
      description: "保護されているトラフィック、その送信経路、対応が必要な事項。",
      help: "「保護中」は、接続済みで、トラフィックがトンネルだけを通る接続です。ダウンロードとアップロードは、実行中のすべての接続の直近 1 秒の合計で、ゲートウェイとポート転送のトラフィックに、厳格に分離された接続のアプリのサンドボックスのトラフィックを加えたものです（厳格な分離では、ポート転送もアプリのサンドボックスに含まれます）。トラフィックの経路は、接続の準備が完了してトラフィックがあるときだけ流れ、一時停止できます。",
      helpText: "「保護中」は、接続済みで、トラフィックがトンネルだけを通る接続です。",
      importProfile: "設定をインポート",
      addConnection: "接続を追加",
    },
    summary: {
      label: "サマリー",
      loading: "サマリーを読み込み中",
      protected: "保護中の接続",
      noConnection: "接続はまだ作成されていません",
      tunnelOnly: "トラフィックはトンネルだけを通ります",
      noReady: "接続済みの出口はありません",
      reading: "状態を読み込み中",
      managerDown: "コアサービスに未接続",
      allConnections: "すべての接続の合計",
      sandboxShare: (rate) => `うちアプリのサンドボックス ${rate}`,
      serving: (count) => `${count} 個のゲートウェイが稼働中`,
    },
    onboarding: {
      title: "はじめに",
      intro: "4 つのステップで、アプリケーションのトラフィックが WireGuard 出口だけを通るようにします。",
      done: "（完了）",
      notDone: "（未完了）",
      profile: {
        title: "WireGuard 設定を用意",
        addAccount: "プロバイダーのアカウントを追加",
        importConf: ".conf をインポート",
        body: "プロバイダーが提供する .conf をインポートするか、Mullvad／AirVPN のアカウントを追加してサーバーを直接選んで作成します。秘密鍵は暗号化して保存されるだけで、読み出すことはできません。",
      },
      connection: {
        title: "接続を作成",
        body: "接続はそれぞれ独立した出口で、同時に複数持てます。",
      },
      gateway: {
        title: "ローカルのゲートウェイを作成",
        body: "アプリケーションは 127.0.0.1 上の SOCKS5 または HTTP のゲートウェイを通じて接続を使います。",
      },
      verify: {
        title: "開始して検証に合格",
        go: "移動",
        body: "ハンドシェイクと DNS の疎通確認の両方に合格してから、接続を受け付けます。",
      },
    },
    attention: {
      title: "要対応",
      items: "要対応の項目",
      none: "現在、対応が必要な項目はありません。",
    },
    system: {
      storeTitle: "ストレージ",
      storeText: "データベースに書き込めません：新しい変更が保存されない可能性があります。",
      clockTitle: "ホストの時刻",
      clockText: (skew) =>
        `ホストの時刻が同期されていません${skew !== null ? `（${skew}）` : ""}：ホストで時刻同期（NTP）を有効にしてください。統計と記録の時刻はホストの時計に従います。`,
    },
    path: {
      title: "トラフィックの経路",
      emptyTitle: "トラフィックの経路はまだありません",
      emptyBody: "最初の接続を作成すると、トラフィックごとの経路がここに表示されます。",
      pause: "アニメーションを一時停止",
      lanes: "接続ごとのトラフィックの経路",
      ports: "ローカルのゲートウェイ",
      legend: (sources, relay) =>
        `${sources} → 接続 → 暗号化された WireGuard トンネル → ${relay ? "入口 → 出口" : "出口"}`,
    },
    node: (title, download, upload) => `${title}、ダウンロード ${download}、アップロード ${upload}`,
    port: {
      title: (name, port, kind, failed, enabled) =>
        `ゲートウェイ ${name}、127.0.0.1:${port}、${kind}${failed ? "、有効にできません" : ""}${enabled ? "" : "、無効"}：通常のプロキシトラフィック（SSH を除く）`,
    },
    pull: {
      label: "SSH ダウンロード",
      count: (active, total) => `${active}／${total} 件のジョブ`,
      title: (total, active) =>
        `SSH ダウンロード：${total} 件のジョブがこの接続のゲートウェイを経由し、${active} 件が進行中（接続中、一覧の取得中、またはダウンロード中）`,
    },
    proxy: {
      label: "SSH プロキシ",
      title: (sessions) =>
        `SSH プロキシ：この接続のゲートウェイを経由して開いている SSH 接続（vpnctl ssh-proxy と、22 番ポートへの接続）${sessions === null ? "、リアルタイムのデータなし" : `、現在 ${sessions} 件`}`,
      sessions: (count) => `${integer.format(count)} 件の接続`,
    },
    sandbox: {
      label: "アプリのサンドボックス",
      title: (names, running) =>
        `アプリのサンドボックス：${names.join("、")}（${running ? (names.length > 1 ? `${running} 個が実行中` : "実行中") : "未実行"}）`,
    },
    lane: {
      noGateways: "ゲートウェイなし",
      generation: (generation) => `第 ${generation} 世代`,
    },
    exit: {
      route: (entry, exit) => `入口 ${entry} → 出口 ${exit}`,
      entryTitle: (server) => `入口 ${server}`,
      entry: "入口",
      exit: "出口",
      noPlace: "場所の表示なし",
      sameServer: (address) => `${address}：入口と出口は同じサーバーです`,
    },
    chart: {
      title: "トラフィック",
      range: "トラフィックグラフの期間",
      tableLabel: "トラフィック：表",
      table: "表",
      scope: (range) => `すべての接続のペイロード、bit/s · ${range}`,
      share: (label, percent) => `${label}が ${percent}`,
      viewInMetrics: "統計で表示",
      stale: "更新できません：前回のデータを表示しています",
      noLiveSample: "リアルタイムのサンプルなし",
      sandboxPart: (rate) => `うちアプリのサンドボックス ${rate}`,
      gaps: (reasons) => `欠損：${reasons.join("、")}`,
      livePending: "リアルタイムのサンプル（まだ保存されていません）",
      plotLabel: (direction, range) =>
        `${direction}（すべての接続のペイロードと、そのうちの SSH ダウンロード、SSH プロキシ、bit/s、${range}）。左右の矢印キーで各点の値を確認するか、表を開いてください`,
      empty: (range) => `${range}のトラフィックデータはありません`,
      loadFailed: "トラフィックデータを取得できません",
      loading: "トラフィックデータを読み込み中",
    },
  },
});
