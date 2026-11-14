// Text of a connection's inspector (instance-inspector.tsx): its header, the conclusion that leads every tab, and the
// tabs 概況 (live traffic, Gateways), 證據 (observed facts, automatic recovery), 資源 (bandwidth caps, OS limits) and
// 設定, and the exit check in its footer. What the worker and the provider report (DNS probe reports, faults, the
// provider's check) is shown as it arrives.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** Shows a phrase of a sentence as a link. */
type Wrap = (text: string) => ReactNode;

export const m = defineMessages({
  en: {
    tabs: {
      /** The tab list's accessible name. */
      label: (name: string) => `Views of ${name}`,
      evidence: "Evidence",
      resources: "Resources",
      settings: "Settings",
    },
    header: {
      /** In place of the place a connection exits, when its WireGuard profile is gone. */
      profileMissing: "The WireGuard profile it uses was not found",
      /** The generation of a connection's running worker. */
      generation: (generation: number) => `Generation ${generation}`,
      idLabel: "Connection ID",
    },
    /** What leads the tabs: a problem, settings waiting for a restart, a DNS failure, an unreadable state. */
    lead: {
      staleTitle: "Settings not applied yet",
      dnsInterruptedTitle: "DNS is interrupted: none of the DNS profile's servers answer",
      /** `name`: the DNS profile's name, if it is known. */
      dnsInterrupted: (name: string | undefined) =>
        `${name === undefined ? "The DNS profile" : `“${name}”`} is set to fail closed and does not ask other DNS servers: meanwhile, apps using the connection cannot resolve names, while connections made directly to an IP work as usual. It recovers by itself once its servers answer again.`,
      dnsFallbackTitle: "None of the DNS profile's servers answer",
      dnsFallback: (name: string | undefined) =>
        `Using the DNS servers the WireGuard profile declares for now: queries still leave only through the tunnel, but not through the servers of ${name === undefined ? "the DNS profile" : `“${name}”`} (its filtering and logging do not apply meanwhile). It switches back by itself once its servers answer again.`,
      checkDns: "Check the DNS profile",
      unknown: "The state cannot be read right now; stop and emergency stop still work.",
    },
    live: {
      title: "Live traffic",
      history: "History",
      waiting: "Waiting for the first data…",
      notRunning: "The connection is not running",
      rss: "Memory",
      rssHint:
        "Resident memory of the worker process (tunnel, DNS cache, the program itself and more); not the use of the “connection buffer” budget",
    },
    gateways: {
      label: (name: string) => `Gateways of ${name}`,
      emptyTitle: "No Gateways yet",
      emptyBody: "Add a local Gateway so that applications can send traffic through this connection.",
      /** The copy button of a Gateway's 127.0.0.1 address. */
      address: "proxy address",
      disabled: "Disabled: not bound with the connection.",
    },
    evidence: {
      lastHandshake: "Last handshake",
      /** Facts of a stopped connection: they describe its last run. */
      lastRun: "Last run",
      noHandshake: "No handshake yet",
      notObserved: "Not observed",
      dnsProbe: "DNS probe",
      dnsProbeHint: (time: string) => `Queried through the tunnel · ${time}`,
      dnsInterrupted: "Interrupted: none of the DNS profile's servers answer, so names do not resolve",
      dnsFallback: "Passed, using the WireGuard profile's DNS: none of the DNS profile's servers answer",
      passed: "Passed",
      failed: "Failed",
      exitEndpoint: "Exit endpoint",
      /** The copy button of the endpoint. */
      endpoint: "endpoint",
      ipv6Set: "IPv6 address configured",
      ipv4Only: "IPv4 only",
      strict: "Strict isolation",
      sandbox: (pid: number, tun: string) => `Sandbox PID ${pid} · only lo and ${tun}`,
      sandboxNotBuilt: "Sandbox not built yet (it is built at start)",
      wgTraffic: "WireGuard traffic",
      wgLastRun: "Encrypted packets in total during the last run",
      wgPackets: "Encrypted packets (with overhead), not application data",
      /** `started`, `ready`: how long ago (null: not ready yet). */
      running: (generation: number, started: string, ready: string | null) =>
        `Generation ${generation} · started ${started}${ready !== null ? ` · ready ${ready}` : ""}`,
      intent: "Intent",
      /** What the latest intent asks for. */
      intentWord: { emergency: "Emergency stop", running: "Run", stopped: "Stop" },
      intentWaiting: (word: string) =>
        `${word} · not written to disk before the core service restarted; waiting for your confirmation`,
      intentDurable: (word: string) => `${word} · written to disk`,
      intentWriting: "Writing to disk…",
      intentFailed: "Cannot write to disk (storage unavailable)",
      observedAt: "State time",
      observed: (time: string) => `Observed ${time}`,
    },
    recovery: {
      title: "Automatic recovery",
      attempts: "Retries",
      next: "Next retry",
      notScheduled: "Not scheduled",
      lastFault: "Latest fault",
    },
    /** The blocklist overlay the running worker enforces. */
    policy: {
      noBlocklists: "No blocklists",
      names: (names: readonly string[]) => names.join(", "),
      applied: (revision: number) => `Version #${revision} applied`,
      pending: (revision: number) => `Applying version #${revision}`,
      running: (revision: number) => `running #${revision}`,
    },
    noWorker: "No running worker",
    resources: {
      title: "Resources and bandwidth",
      caps: "Bandwidth limits",
      capsPending: "Applying the saved limits…",
      capsApplied: "Applied by the worker · shared by every Gateway",
      capsSaved: "Saved · applied once the connection starts",
      shaping: "Limiting",
      shapingHint: "The latest sampling interval; TCP waits at the limit, UDP over the limit is dropped",
      download: (text: string) => `Download: ${text}`,
      upload: (text: string) => `Upload: ${text}`,
      process: "Process limits",
      notReported: "Not reported by the worker",
    },
    /** How a capped direction fared in the last interval. */
    shaping: {
      limited: (percent: number) => `limited ${percent}% of the time`,
      dropped: (share: string, rate: string) => `${share} · UDP dropped ${rate}/s`,
    },
    /** What the running worker's transport does now. */
    transport: {
      band: (name: string) => `Now using “${name}”`,
      noRoundTrip: "Round-trip time not measured yet",
      roundTrip: (ms: number) => `Round trip ${ms} ms`,
      newFlows: (send: string, receive: string) => `New connections: send ${send}, receive ${receive}`,
      grown: (count: number) => `Buffers grown ${count} ${count === 1 ? "time" : "times"}`,
      refused: (count: number) =>
        `${count} ${count === 1 ? "time" : "times"} not grown for lack of connection buffer budget`,
      kernel: (receive: string, send: string) =>
        `Kernel TCP buffer limits of the sandbox: receive ${receive}, send ${send}`,
    },
    settings: {
      gone: "The profile no longer exists",
      /** In place of a DNS profile's name that is not loaded. */
      dnsProfile: "DNS profile",
      profileDns: "The DNS the configuration file declares (UDP; TCP when an answer is truncated)",
      security: "Security profile",
      defaultSecurity: (link: Wrap): ReactNode => (
        <>
          Default security policy: only public internet addresses are allowed, the {link("built-in IP blocklists")}{" "}
          apply and auto-ban is on
        </>
      ),
      transport: "Transport profile",
      transportNotReported: "The worker has not reported yet",
      transportApplies: "Saved changes apply at once to the connections opened from then on",
      loading: "Loading…",
      limits: "Resource limits",
      limitsHint: (limit: number, byMemory: boolean) =>
        `At most ${limit} TCP connections in practice${byMemory ? " (bound by the connection buffer)" : ""}; the connection buffer is a budget for send and receive buffers, not process memory`,
      limitsValue: (tcp: number, udp: number, mib: number) => `TCP ${tcp} · UDP ${udp} · connection buffer ${mib} MiB`,
    },
    /** The exit check in the footer. */
    exit: {
      hint: "Look up its exit IP and location through this connection.",
      notReady: "The exit IP can be checked once the connection is ready.",
      same: (exit: string) => `The provider's check says the exit is ${exit}, the same as the configured exit.`,
      differs: (named: string, configured: string) =>
        `The provider's check says the exit is ${named}, but the configured exit is ${configured}: restart the connection, then check again.`,
      /** `latency`: how long the check took, in ms. */
      via: (latency: number | null) =>
        `Queried through this connection's tunnel${latency !== null ? ` · ${latency} ms` : ""}; only the provider's own answer can prove the exit is theirs.`,
      /** What a failed check is reported as (the notification adds that it failed). */
      intent: "Check the exit",
    },
    /** The worker's DNS probe report, one line per server. */
    dnsReport: { servers: "Result of each server" },
  },
  "zh-TW": {
    tabs: {
      label: (name) => `${name} 的檢視`,
      evidence: "證據",
      resources: "資源",
      settings: "設定",
    },
    header: {
      profileMissing: "找不到使用的 WireGuard 設定",
      generation: (generation) => `第 ${generation} 代`,
      idLabel: "連線 ID",
    },
    lead: {
      staleTitle: "設定尚未套用",
      dnsInterruptedTitle: "DNS 已中斷：DNS 設定的伺服器都沒有回應",
      dnsInterrupted: (name) =>
        `「${name ?? "DNS 設定"}」設定為失敗時中斷，不改問其他 DNS：這段時間連線的 App 無法解析名稱，直接用 IP 的連線照常。它的伺服器恢復回應後自動恢復。`,
      dnsFallbackTitle: "DNS 設定的伺服器都沒有回應",
      dnsFallback: (name) =>
        `暫時改用 WireGuard 設定宣告的 DNS：查詢同樣只經 tunnel 送出，但不經「${name ?? "DNS 設定"}」的伺服器（它的過濾與紀錄這段時間不適用）。它的伺服器恢復回應後自動改回。`,
      checkDns: "檢查 DNS 設定",
      unknown: "目前讀不到狀態；停止與急停仍可使用。",
    },
    live: {
      title: "即時流量",
      history: "歷史數據",
      waiting: "等待第一筆數據…",
      notRunning: "連線未執行",
      rss: "程序 RSS",
      rssHint: "worker 程序的常駐記憶體（tunnel、DNS 快取、程式本身等）；不是「連線緩衝」預算的用量",
    },
    gateways: {
      label: (name) => `${name} 的代理埠`,
      emptyTitle: "還沒有代理埠",
      emptyBody: "新增一個本機代理埠，應用程式才能經這條連線送出流量。",
      address: "代理位址",
      disabled: "已停用：不會隨連線綁定。",
    },
    evidence: {
      lastHandshake: "最後握手",
      lastRun: "上次執行",
      noHandshake: "尚未握手",
      notObserved: "未觀測",
      dnsProbe: "DNS 探測",
      dnsProbeHint: (time) => `經 tunnel 查詢 · ${time}`,
      dnsInterrupted: "中斷：DNS 設定的伺服器都沒有回應，名稱無法解析",
      dnsFallback: "通過，改用 WireGuard 設定的 DNS：DNS 設定的伺服器都沒有回應",
      passed: "通過",
      failed: "失敗",
      exitEndpoint: "出口端點",
      endpoint: "端點",
      ipv6Set: "已設定 IPv6 位址",
      ipv4Only: "只有 IPv4",
      strict: "嚴格隔離",
      sandbox: (pid, tun) => `沙箱 PID ${pid} · 只有 lo 與 ${tun}`,
      sandboxNotBuilt: "沙箱尚未建立（啟動時建立）",
      wgTraffic: "WireGuard 流量",
      wgLastRun: "上次執行的累計加密封包",
      wgPackets: "加密封包（含額外負載），非應用資料量",
      running: (generation, started, ready) =>
        `第 ${generation} 代 · ${started}啟動${ready !== null ? ` · ${ready}就緒` : ""}`,
      intent: "操作意圖",
      intentWord: { emergency: "急停", running: "執行", stopped: "停止" },
      intentWaiting: (word) => `${word} · 核心服務重新啟動前沒有寫入磁碟，等你確認`,
      intentDurable: (word) => `${word} · 已寫入磁碟`,
      intentWriting: "寫入磁碟中…",
      intentFailed: "無法寫入磁碟（儲存不可用）",
      observedAt: "狀態時間",
      observed: (time) => `${time}觀測`,
    },
    recovery: {
      title: "自動恢復",
      attempts: "重試次數",
      next: "下次重試",
      notScheduled: "沒有排定",
      lastFault: "最近故障",
    },
    policy: {
      noBlocklists: "沒有封鎖清單",
      names: (names) => names.join("、"),
      applied: (revision) => `版本 #${revision} 已套用`,
      pending: (revision) => `版本 #${revision} 套用中`,
      running: (revision) => `目前執行 #${revision}`,
    },
    noWorker: "沒有執行中的 worker",
    resources: {
      title: "資源與頻寬",
      caps: "頻寬上限",
      capsPending: "儲存的上限套用中…",
      capsApplied: "worker 已套用 · 所有代理埠共用",
      capsSaved: "已儲存 · 連線啟動後套用",
      shaping: "上限作用",
      shapingHint: "最近一次取樣區間；TCP 在上限下等待，超過上限的 UDP 被丟棄",
      download: (text) => `下載：${text}`,
      upload: (text) => `上傳：${text}`,
      process: "程序上限",
      notReported: "worker 沒有回報",
    },
    shaping: {
      limited: (percent) => `${percent}% 的時間受限`,
      dropped: (share, rate) => `${share} · UDP 丟棄 ${rate}/s`,
    },
    transport: {
      band: (name) => `目前套用「${name}」`,
      noRoundTrip: "尚未量到往返時間",
      roundTrip: (ms) => `往返 ${ms} 毫秒`,
      newFlows: (send, receive) => `新連線：送出 ${send}、接收 ${receive}`,
      grown: (count) => `已放大緩衝 ${count} 次`,
      refused: (count) => `${count} 次因連線緩衝預算不足沒有放大`,
      kernel: (receive, send) => `沙箱的核心 TCP 緩衝上限：接收 ${receive}、送出 ${send}`,
    },
    settings: {
      gone: "設定已不存在",
      dnsProfile: "DNS 設定",
      profileDns: "設定檔宣告的 DNS（UDP；回應被截斷時改用 TCP）",
      security: "安全設定",
      defaultSecurity: (link) => (
        <>預設安全政策：只允許公開網際網路位址，套用{link("內建 IP 封鎖清單")}並開啟自動封鎖</>
      ),
      transport: "傳輸設定",
      transportNotReported: "worker 還沒有回報",
      transportApplies: "儲存後立即套用到之後建立的連線",
      loading: "載入中…",
      limits: "資源上限",
      limitsHint: (limit, byMemory) =>
        `TCP 實際最多 ${limit} 條${byMemory ? "（受連線緩衝限制）" : ""}；連線緩衝是收發緩衝的預算，不是程序記憶體`,
      limitsValue: (tcp, udp, mib) => `TCP ${tcp} · UDP ${udp} · 連線緩衝 ${mib} MiB`,
    },
    exit: {
      hint: "經這條連線查詢它的出口 IP 與地點。",
      notReady: "連線就緒後可以檢查出口 IP。",
      same: (exit) => `供應商的檢查說出口是 ${exit}，與設定的出口相同。`,
      differs: (named, configured) =>
        `供應商的檢查說出口是 ${named}，設定的出口是 ${configured}：重新啟動連線後再檢查一次。`,
      via: (latency) =>
        `經這條連線的 tunnel 查詢${latency !== null ? ` · ${latency} ms` : ""}；只有供應商自己的答案能證明出口屬於它。`,
      intent: "檢查出口",
    },
    dnsReport: { servers: "各伺服器的結果" },
  },
  ja: {
    tabs: {
      label: (name) => `${name} の表示`,
      evidence: "エビデンス",
      resources: "リソース",
      settings: "設定",
    },
    header: {
      profileMissing: "使用する WireGuard 設定が見つかりません",
      generation: (generation) => `第 ${generation} 世代`,
      idLabel: "接続 ID",
    },
    lead: {
      staleTitle: "設定はまだ適用されていません",
      dnsInterruptedTitle: "DNS が中断しています：DNS 設定のサーバーがどれも応答しません",
      dnsInterrupted: (name) =>
        `「${name ?? "DNS 設定"}」は失敗時に中断する設定で、ほかの DNS には問い合わせません：この間、接続を使うアプリは名前解決できませんが、IP を直接指定した通信はそのまま使えます。サーバーが応答するようになると自動的に復旧します。`,
      dnsFallbackTitle: "DNS 設定のサーバーがどれも応答しません",
      dnsFallback: (name) =>
        `一時的に WireGuard 設定で宣言された DNS を使用しています：問い合わせは引き続きトンネルだけを通りますが、「${name ?? "DNS 設定"}」のサーバーは経由しません（この間、そのフィルタリングと記録は適用されません）。サーバーが応答するようになると自動的に戻ります。`,
      checkDns: "DNS 設定を確認",
      unknown: "現在、状態を読み取れません。停止と緊急停止は引き続き使えます。",
    },
    live: {
      title: "リアルタイムトラフィック",
      history: "履歴",
      waiting: "最初のデータを待っています…",
      notRunning: "接続は実行されていません",
      rss: "メモリ",
      rssHint:
        "worker プロセスの常駐メモリ（トンネル、DNS キャッシュ、プログラム本体など）。「接続バッファー」の予算の使用量ではありません",
    },
    gateways: {
      label: (name) => `${name} のゲートウェイ`,
      emptyTitle: "ゲートウェイはまだありません",
      emptyBody: "ローカルのゲートウェイを追加すると、アプリケーションがこの接続経由でトラフィックを送信できます。",
      address: "プロキシアドレス",
      disabled: "無効：接続と一緒にバインドされません。",
    },
    evidence: {
      lastHandshake: "最後のハンドシェイク",
      lastRun: "前回の実行",
      noHandshake: "まだハンドシェイクしていません",
      notObserved: "未観測",
      dnsProbe: "DNS の疎通確認",
      dnsProbeHint: (time) => `トンネル経由で照会 · ${time}`,
      dnsInterrupted: "中断：DNS 設定のサーバーがどれも応答せず、名前解決できません",
      dnsFallback: "成功（WireGuard 設定の DNS を使用）：DNS 設定のサーバーがどれも応答しません",
      passed: "成功",
      failed: "失敗",
      exitEndpoint: "出口エンドポイント",
      endpoint: "エンドポイント",
      ipv6Set: "IPv6 アドレス設定済み",
      ipv4Only: "IPv4 のみ",
      strict: "厳格な分離",
      sandbox: (pid, tun) => `サンドボックス PID ${pid} · lo と ${tun} のみ`,
      sandboxNotBuilt: "サンドボックスはまだ作成されていません（開始時に作成）",
      wgTraffic: "WireGuard トラフィック",
      wgLastRun: "前回の実行での暗号化パケットの累計",
      wgPackets: "暗号化パケット（オーバーヘッドを含む）。アプリケーションのデータ量ではありません",
      running: (generation, started, ready) =>
        `第 ${generation} 世代 · 開始：${started}${ready !== null ? ` · 準備完了：${ready}` : ""}`,
      intent: "目標の状態",
      intentWord: { emergency: "緊急停止", running: "実行", stopped: "停止" },
      intentWaiting: (word) => `${word} · コアサービスの再起動前にディスクへ書き込まれていません。確認を待っています`,
      intentDurable: (word) => `${word} · ディスクに書き込み済み`,
      intentWriting: "ディスクに書き込み中…",
      intentFailed: "ディスクに書き込めません（ストレージが使用できません）",
      observedAt: "状態の時刻",
      observed: (time) => `観測：${time}`,
    },
    recovery: {
      title: "自動復旧",
      attempts: "再試行回数",
      next: "次の再試行",
      notScheduled: "予定なし",
      lastFault: "直近の障害",
    },
    policy: {
      noBlocklists: "ブロックリストなし",
      names: (names) => names.join("、"),
      applied: (revision) => `バージョン #${revision} を適用済み`,
      pending: (revision) => `バージョン #${revision} を適用中`,
      running: (revision) => `現在は #${revision} を実行中`,
    },
    noWorker: "実行中の worker はありません",
    resources: {
      title: "リソースと帯域幅",
      caps: "帯域幅の上限",
      capsPending: "保存した上限を適用中…",
      capsApplied: "worker が適用済み · すべてのゲートウェイで共有",
      capsSaved: "保存済み · 接続の開始後に適用",
      shaping: "上限の作用",
      shapingHint: "直近のサンプリング区間。TCP は上限で待機し、上限を超えた UDP は破棄されます",
      download: (text) => `ダウンロード：${text}`,
      upload: (text) => `アップロード：${text}`,
      process: "プロセスの上限",
      notReported: "worker から報告がありません",
    },
    shaping: {
      limited: (percent) => `${percent}% の時間で制限`,
      dropped: (share, rate) => `${share} · UDP 破棄 ${rate}/s`,
    },
    transport: {
      band: (name) => `現在は「${name}」を適用`,
      noRoundTrip: "往復時間はまだ測定されていません",
      roundTrip: (ms) => `往復 ${ms} ミリ秒`,
      newFlows: (send, receive) => `新しい接続：送信 ${send}、受信 ${receive}`,
      grown: (count) => `バッファーを ${count} 回拡大`,
      refused: (count) => `接続バッファーの予算不足で ${count} 回拡大できず`,
      kernel: (receive, send) => `サンドボックスのカーネル TCP バッファー上限：受信 ${receive}、送信 ${send}`,
    },
    settings: {
      gone: "設定はもう存在しません",
      dnsProfile: "DNS 設定",
      profileDns: "設定ファイルで宣言された DNS（UDP。応答が切り詰められたときは TCP）",
      security: "セキュリティ設定",
      defaultSecurity: (link) => (
        <>
          既定のセキュリティポリシー：公開インターネットのアドレスだけを許可し、{link("組み込みの IP ブロックリスト")}
          を適用して、自動ブロックを有効にします
        </>
      ),
      transport: "トランスポート設定",
      transportNotReported: "worker はまだ報告していません",
      transportApplies: "保存するとすぐに、その後に開く接続に適用されます",
      loading: "読み込み中…",
      limits: "リソースの上限",
      limitsHint: (limit, byMemory) =>
        `TCP 接続は実際には最大 ${limit} 本${byMemory ? "（接続バッファーによる制限）" : ""}。接続バッファーは送受信バッファーの予算で、プロセスのメモリではありません`,
      limitsValue: (tcp, udp, mib) => `TCP ${tcp} · UDP ${udp} · 接続バッファー ${mib} MiB`,
    },
    exit: {
      hint: "この接続経由で出口 IP と場所を照会します。",
      notReady: "接続の準備が完了すると、出口 IP を確認できます。",
      same: (exit) => `プロバイダーのチェックでは、出口は ${exit} で、設定した出口と同じです。`,
      differs: (named, configured) =>
        `プロバイダーのチェックでは出口は ${named}、設定した出口は ${configured} です：接続を再起動してから、もう一度確認してください。`,
      via: (latency) =>
        `この接続のトンネル経由で照会${latency !== null ? ` · ${latency} ms` : ""}。出口がプロバイダーのものだと証明できるのは、プロバイダー自身の回答だけです。`,
      intent: "出口の確認",
    },
    dnsReport: { servers: "サーバーごとの結果" },
  },
});
