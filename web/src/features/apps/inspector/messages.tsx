// Text of the managed-App inspector: its tabs, the run, the process tree, listening ports, port forwards, the output
// log, the executable and settings, and under `sandbox` the live traffic of a strict App's sandbox. A sub-area of the
// Managed apps page (../messages.ts), kept apart for size; a .tsx: a few sentences carry markup
// (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages, intlLocale } from "@/i18n";

/** A count as this language writes it ("1,234"). */
function num(value: number): string {
  return value.toLocaleString(intlLocale);
}

export const m = defineMessages({
  en: {
    tab: { ports: "Ports", output: "Output" },
    /** CPU time from ten minutes up, and from ten hours up. */
    minutesSeconds: (minutes: number, seconds: number) => `${minutes} min ${seconds} s`,
    hours: (hours: number) => `${hours} h`,
    exitCode: (code: number) => `Exit code ${code}`,
    /** `name`: the signal's name (SIGKILL), when it is a well-known one. */
    signal: (signal: number, name: string | undefined) => `Signal ${signal}${name ? ` (${name})` : ""}`,
    exitUnknown: "Exit status unknown",
    noProcesses: "No process is running.",
    readingProcesses: "Reading the process list",
    processesFailed: "Could not read the process list",
    processTree: "Process tree",
    program: "Program",
    cpuTime: "CPU time",
    memory: "Memory",
    processTitle: (name: string, parent: number, started: string) =>
      `${name} · parent process ${parent} · started ${started}`,
    /** `count`: the number of processes as an element; `read`: when the list was read ("3 seconds ago"). */
    processSummary: (count: ReactNode, read: string, truncated: boolean, total: number): ReactNode => (
      <>
        {count} {total === 1 ? "process" : "processes"}
        {truncated ? " (only some are listed)" : ""} · read {read}; identified by PID and start time, so a reused PID is
        never counted.
      </>
    ),
    notMeasured: "Not measured (checked every 2 seconds while the app runs).",
    listenersOf: (name: string) => `Ports ${name} listens on`,
    reachable: "Reachable by other hosts",
    noListeners: "No listening TCP port.",
    enforcedListeners: "Under enforced proxy, an app that listens on a non-loopback address is stopped.",
    forwards: "Port forwards",
    forwardsTo: (name: string) => `Port forwards that deliver to ${name}`,
    noForwards: "No port forward delivers to this app",
    noForwardsHint:
      "Inbound connections the provider forwards to the tunnel address can be forwarded to a port this app listens on locally.",
    outputLog: "Output log",
    refreshLog: "Refresh the output log",
    readingLog: "Reading the output log",
    logFailed: "Could not read the output log",
    noOutput: "No output yet. The app's stdout and stderr are recorded here.",
    outputLabel: "The app's output (newest at the bottom)",
    logSummary: (count: number, truncated: boolean) =>
      `Last ${count} ${count === 1 ? "line" : "lines"}${truncated ? " (earlier ones are left out)" : ""}; past 2 MiB the log moves to .1, where one copy is kept.`,
    /** `digest`: the approved SHA-256, shortened, as an element; `when`: the time of the approval. */
    approvedNote: (digest: ReactNode, when: string): ReactNode => (
      <>
        Approved SHA-256 {digest} ({when}); every start compares it again and does not start on a difference.
      </>
    ),
    /** `state`: the connection's state as the connection pages name it. */
    connectionState: (name: string, state: string) => `Connection “${name}”: ${state}`,
    waitsForConnection:
      "The app's connections through the Gateway are refused for now and never fall back to the ordinary network; they resume by themselves once the connection is ready.",
    notApplied: "Settings not applied yet",
    /** What the copy button next to the ID copies. */
    idLabel: "managed app ID",
    actionsOf: (name: string) => `Actions for ${name}`,
    viewsOf: (name: string) => `Views of ${name}`,
    runtime: "Runtime",
    /** `when`: relative ("3 seconds ago"). */
    observed: (when: string) => `Observed ${when}`,
    unknownState: "Unknown (the core service is not connected)",
    rootProcess: "Root process",
    /** `running`: the root process is there now; otherwise the time is the last run's. */
    startedAt: (when: string, running: boolean) => (running ? `Started ${when}` : `Last started ${when}`),
    processCount: "Process count",
    isolation: "Isolation",
    seatbeltDenials: "Seatbelt denials",
    seatbeltDenialsHint:
      "Denials in the system log (unified log) that are tagged with this run, updated about every 30 seconds",
    systemLogUnreadable: "Cannot read the system log",
    denials: (count: number) => String(count),
    lastExit: "Last exit",
    intent: "Intent",
    desired: { running: "Run", stopped: "Stop" },
    persistence: {
      durable: "Written to disk",
      pending: "Writing to disk…",
      unavailable: "Cannot be written to disk",
    },
    notObserved: "Not observed",
    /** The resource limits the App's settings ask for (next to the ones in force). */
    limitsSet: "Configured",
    noLimits: "None set (unlimited)",
    limitsInForce: "Limits in force",
    notReported: "The core service did not report them",
    listeningPorts: "Listening ports",
    path: "Path",
    /** The file that runs, where it is not the configured path itself. */
    resolved: "Actually runs",
    recognisedAs: "Recognised as",
    approval: "Approval",
    addedByManager: "Added by VPN Manager",
    addedByManagerHint: "The browser's own data directory, placed before the app's arguments",
    emptyArgument: "(empty string)",
    homeLabel: "Private home directory",
    homeHint: "HOME; {app_home} becomes this path",
    homeNotReported: "The core service did not report the data directory",
    onlyManagerEnv: "Only the variables VPN Manager sets",
    writable: "Writable",
    writesNotConfined: "“Confine writes” is off",
    writableAnywhere: "Anywhere its user can write",
    landlockHint: "Everything else is read-only (Linux Landlock); /dev is writable too",
    privateDirs: "Private directories (HOME, TMPDIR)",
    onlyPrivateDirs: "Only the private directories",
    stopGrace: "Stop grace period",
    /** `seconds`: the number as an element; `count`: the same number. */
    killedAfter: (seconds: ReactNode, count: number): ReactNode => (
      <>
        Killed after {seconds} {count === 1 ? "second" : "seconds"}
      </>
    ),
    recovery: "Recovery after a restart",
    noRestartOnRecovery: "Do not start again automatically",
    isolationMode: "Isolation mode",
    modeUnavailable: (reason: string | null) => `This host cannot use it: ${reason ?? "unknown reason"}`,
    /** The live traffic of a strict App's sandbox. */
    sandbox: {
      evicted: (count: number) => `Evicted ${num(count)} ${count === 1 ? "flow" : "flows"} that had no reply`,
      tableFull: (count: number) => `Table full: refused ${num(count)} new ${count === 1 ? "flow" : "flows"}`,
      /** What the flow tables did, one part each. */
      notes: (parts: readonly string[]) => parts.join(" · "),
      noConnection: "Its connection was not found",
      connectionNotRunning: (name: string) => `Connection “${name}” is not running`,
      noLiveData: "No live figures yet",
      latestSecondAll: "The app sandbox's latest second, inbound through port forwards included",
      history: "History",
      shared: (count: number) => `${count} apps share this app sandbox`,
      sharedDetail: (connection: string, app: string, others: readonly string[]) =>
        `The strictly isolated apps of connection “${connection}” are all in one app sandbox: this is the combined traffic of “${app}” and ${others.map((o) => `“${o}”`).join(", ")}, and it cannot be told apart by app.`,
      latestSecond: "Latest second",
      trackedFlows: "Tracked flows",
      trackedFlowsHint:
        "The apps' own connections that the packet filter is tracking; those that come in through port forwards are not among them",
      flowTable: "Flow table",
      flowTableHint: "Since this generation of the connection; flows that had no reply give up their place first",
      counted:
        "Counted is the TCP and UDP data the apps send and receive: their own connections (retransmitted packets count too) and connections that come in through port forwards; the Gateways and DNS of the connection are not included. All of it is already part of the connection's traffic.",
    },
  },
  "zh-TW": {
    tab: { ports: "連接埠", output: "輸出" },
    minutesSeconds: (minutes, seconds) => `${minutes} 分 ${seconds} 秒`,
    hours: (hours) => `${hours} 小時`,
    exitCode: (code) => `結束碼 ${code}`,
    signal: (signal, name) => `訊號 ${signal}${name ? `（${name}）` : ""}`,
    exitUnknown: "結束狀態不明",
    noProcesses: "沒有執行中的程序。",
    readingProcesses: "讀取程序清單",
    processesFailed: "無法讀取程序清單",
    processTree: "程序樹",
    program: "程式",
    cpuTime: "CPU 時間",
    memory: "記憶體",
    processTitle: (name, parent, started) => `${name} · 父程序 ${parent} · ${started} 啟動`,
    processSummary: (count, read, truncated) => (
      <>
        {count} 個程序{truncated ? "（只列出一部分）" : ""} · {read}讀取；以 PID 與啟動時間辨識，不會把重複使用的 PID
        算進來。
      </>
    ),
    notMeasured: "未量測（App 執行時每 2 秒檢查一次）。",
    listenersOf: (name) => `${name} 監聽的連接埠`,
    reachable: "其他主機可連入",
    noListeners: "沒有監聽中的 TCP 埠。",
    enforcedListeners: "強制代理模式下，在非本機位址監聽的 App 會被停止。",
    forwards: "轉發",
    forwardsTo: (name) => `送到 ${name} 的轉發`,
    noForwards: "沒有轉發送到這個 App",
    noForwardsHint: "供應商轉到 tunnel 位址的連入，可以轉發給這個 App 在本機監聽的 port。",
    outputLog: "輸出紀錄",
    refreshLog: "重新整理輸出紀錄",
    readingLog: "讀取輸出紀錄",
    logFailed: "無法讀取輸出紀錄",
    noOutput: "還沒有輸出。App 的 stdout 與 stderr 會記錄在這裡。",
    outputLabel: "App 的輸出（最新在下方）",
    logSummary: (count, truncated) =>
      `最後 ${count} 行${truncated ? "（更早的已略過）" : ""}；超過 2 MiB 時移到 .1 保留一份。`,
    approvedNote: (digest, when) => (
      <>
        已核准 SHA-256 {digest}（{when}）；每次啟動都重新比對，不同就不啟動。
      </>
    ),
    connectionState: (name, state) => `連線「${name}」${state}`,
    waitsForConnection: "App 經代理埠的連線目前會被拒絕，不會改走一般網路；連線就緒後自動恢復。",
    notApplied: "設定尚未套用",
    idLabel: "受管 App ID",
    actionsOf: (name) => `${name} 的操作`,
    viewsOf: (name) => `${name} 的檢視`,
    runtime: "執行",
    observed: (when) => `${when}觀測`,
    unknownState: "未知（核心服務未連線）",
    rootProcess: "根程序",
    startedAt: (when, running) => `${running ? "" : "上次 "}${when} 啟動`,
    processCount: "程序數",
    isolation: "隔離",
    seatbeltDenials: "Seatbelt 拒絕",
    seatbeltDenialsHint: "系統紀錄（unified log）中標記為這次執行的拒絕，約每 30 秒更新",
    systemLogUnreadable: "無法讀取系統紀錄",
    denials: (count) => `${count} 次`,
    lastExit: "上次結束",
    intent: "操作意圖",
    desired: { running: "執行", stopped: "停止" },
    persistence: { durable: "已寫入磁碟", pending: "寫入磁碟中…", unavailable: "無法寫入磁碟" },
    notObserved: "未觀測",
    limitsSet: "設定",
    noLimits: "沒有設定（不限）",
    limitsInForce: "生效的上限",
    notReported: "核心服務沒有回報",
    listeningPorts: "監聽的連接埠",
    path: "路徑",
    resolved: "實際執行",
    recognisedAs: "辨識為",
    approval: "核准",
    addedByManager: "VPN Manager 加上",
    addedByManagerHint: "瀏覽器自己的資料目錄，排在 App 的參數前面",
    emptyArgument: "（空字串）",
    homeLabel: "私有家目錄",
    homeHint: "HOME；{app_home} 會換成這個路徑",
    homeNotReported: "核心服務未回報資料目錄",
    onlyManagerEnv: "只有 VPN Manager 設定的變數",
    writable: "可寫入",
    writesNotConfined: "沒有開啟「限制寫入位置」",
    writableAnywhere: "它的使用者能寫的任何地方",
    landlockHint: "其他地方只能讀（Linux Landlock），另含 /dev",
    privateDirs: "私有目錄（HOME、TMPDIR）",
    onlyPrivateDirs: "只有私有目錄",
    stopGrace: "停止前等待",
    killedAfter: (seconds) => <>{seconds} 秒後強制結束</>,
    recovery: "重新啟動恢復",
    noRestartOnRecovery: "不自動再啟動",
    isolationMode: "隔離方式",
    modeUnavailable: (reason) => `這台主機無法使用：${reason ?? "未知原因"}`,
    sandbox: {
      evicted: (count) => `淘汰 ${num(count)} 個沒有回應的流`,
      tableFull: (count) => `表已滿、拒絕 ${num(count)} 個新的流`,
      notes: (parts) => parts.join("；"),
      noConnection: "找不到所屬連線",
      connectionNotRunning: (name) => `連線「${name}」沒有執行`,
      noLiveData: "還沒有即時數據",
      latestSecondAll: "App 沙箱最近一秒，含轉發連入",
      history: "歷史數據",
      shared: (count) => `${count} 個 App 共用這個 App 沙箱`,
      sharedDetail: (connection, app, others) =>
        `連線「${connection}」的嚴格隔離 App 都在同一個 App 沙箱裡：這裡是「${app}」與「${others.join("」「")}」合計的流量，分不出各個 App。`,
      latestSecond: "最近一秒",
      trackedFlows: "追蹤中的流",
      trackedFlowsHint: "封包過濾正在追蹤的 App 自己的連線；經轉發連入的不在其中",
      flowTable: "流量表",
      flowTableHint: "這一代連線以來；沒有回應的流最先讓出位置",
      counted:
        "算的是 App 收發的 TCP 與 UDP 資料：App 自己的連線（重送的封包也算）與經轉發連入的連線；所屬連線的代理埠與 DNS 不算在內。這些都已計入連線的流量。",
    },
  },
  ja: {
    tab: { ports: "ポート", output: "出力" },
    minutesSeconds: (minutes, seconds) => `${minutes} 分 ${seconds} 秒`,
    hours: (hours) => `${hours} 時間`,
    exitCode: (code) => `終了コード ${code}`,
    signal: (signal, name) => `シグナル ${signal}${name ? `（${name}）` : ""}`,
    exitUnknown: "終了状態は不明",
    noProcesses: "実行中のプロセスはありません。",
    readingProcesses: "プロセス一覧を読み込み中",
    processesFailed: "プロセス一覧を読み込めませんでした",
    processTree: "プロセスツリー",
    program: "プログラム",
    cpuTime: "CPU 時間",
    memory: "メモリ",
    processTitle: (name, parent, started) => `${name} · 親プロセス ${parent} · ${started} に開始`,
    processSummary: (count, read, truncated) => (
      <>
        {count} 個のプロセス{truncated ? "（一部のみ表示）" : ""} · {read}に取得。PID
        と開始時刻で識別するため、再利用された PID を数えることはありません。
      </>
    ),
    notMeasured: "未計測（アプリの実行中は 2 秒ごとに確認します）。",
    listenersOf: (name) => `${name} が待ち受けているポート`,
    reachable: "ほかのホストから接続可能",
    noListeners: "待ち受け中の TCP ポートはありません。",
    enforcedListeners: "強制プロキシでは、ループバック以外のアドレスで待ち受けたアプリは停止されます。",
    forwards: "ポート転送",
    forwardsTo: (name) => `${name} に届けるポート転送`,
    noForwards: "このアプリに届けるポート転送はありません",
    noForwardsHint:
      "プロバイダーがトンネルのアドレスに転送した着信を、このアプリがローカルで待ち受けているポートに転送できます。",
    outputLog: "出力ログ",
    refreshLog: "出力ログを更新",
    readingLog: "出力ログを読み込み中",
    logFailed: "出力ログを読み込めませんでした",
    noOutput: "まだ出力はありません。アプリの stdout と stderr がここに記録されます。",
    outputLabel: "アプリの出力（最新は下）",
    logSummary: (count, truncated) =>
      `最後の ${count} 行${truncated ? "（それより前は省略）" : ""}。2 MiB を超えると .1 に移して 1 つだけ保持します。`,
    approvedNote: (digest, when) => (
      <>
        承認済みの SHA-256 {digest}（{when}）。開始のたびに照合し直し、異なれば開始しません。
      </>
    ),
    connectionState: (name, state) => `接続「${name}」：${state}`,
    waitsForConnection:
      "ゲートウェイ経由のアプリの接続は現在拒否され、通常のネットワークには切り替わりません。接続の準備ができると自動的に再開します。",
    notApplied: "設定が未適用",
    idLabel: "管理対象アプリ ID",
    actionsOf: (name) => `${name} の操作`,
    viewsOf: (name) => `${name} の表示`,
    runtime: "実行",
    observed: (when) => `観測：${when}`,
    unknownState: "不明（コアサービスに未接続）",
    rootProcess: "ルートプロセス",
    startedAt: (when, running) => `${running ? "" : "前回 "}${when} に開始`,
    processCount: "プロセス数",
    isolation: "分離",
    seatbeltDenials: "Seatbelt の拒否",
    seatbeltDenialsHint: "システムログ（unified log）のうち今回の実行の印が付いた拒否。約 30 秒ごとに更新",
    systemLogUnreadable: "システムログを読み取れません",
    denials: (count) => `${count} 回`,
    lastExit: "前回の終了",
    intent: "操作の意図",
    desired: { running: "実行", stopped: "停止" },
    persistence: {
      durable: "ディスクに書き込み済み",
      pending: "ディスクに書き込み中…",
      unavailable: "ディスクに書き込めません",
    },
    notObserved: "未観測",
    limitsSet: "設定値",
    noLimits: "設定なし（無制限）",
    limitsInForce: "有効な上限",
    notReported: "コアサービスが報告していません",
    listeningPorts: "待ち受けポート",
    path: "パス",
    resolved: "実際に実行されるファイル",
    recognisedAs: "識別結果",
    approval: "承認",
    addedByManager: "VPN Manager が追加",
    addedByManagerHint: "ブラウザー専用のデータディレクトリ。アプリの引数の前に置かれます",
    emptyArgument: "（空文字列）",
    homeLabel: "専用のホームディレクトリ",
    homeHint: "HOME。{app_home} はこのパスに置き換わります",
    homeNotReported: "コアサービスがデータディレクトリを報告していません",
    onlyManagerEnv: "VPN Manager が設定する変数のみ",
    writable: "書き込み可能",
    writesNotConfined: "「書き込み先を制限」がオフです",
    writableAnywhere: "そのユーザーが書き込めるすべての場所",
    landlockHint: "それ以外は読み取り専用（Linux Landlock）。/dev も書き込み可能",
    privateDirs: "専用ディレクトリ（HOME、TMPDIR）",
    onlyPrivateDirs: "専用ディレクトリのみ",
    stopGrace: "停止の猶予時間",
    killedAfter: (seconds) => <>{seconds} 秒後に強制終了</>,
    recovery: "再起動後の復旧",
    noRestartOnRecovery: "自動では開始しない",
    isolationMode: "分離方式",
    modeUnavailable: (reason) => `このホストでは使えません：${reason ?? "原因不明"}`,
    sandbox: {
      evicted: (count) => `応答のないフロー ${num(count)} 件を破棄`,
      tableFull: (count) => `テーブルが満杯：新しいフロー ${num(count)} 件を拒否`,
      notes: (parts) => parts.join(" · "),
      noConnection: "所属する接続が見つかりません",
      connectionNotRunning: (name) => `接続「${name}」は実行されていません`,
      noLiveData: "リアルタイムのデータはまだありません",
      latestSecondAll: "アプリのサンドボックスの直近 1 秒。ポート転送経由の着信を含む",
      history: "履歴データ",
      shared: (count) => `${count} 件のアプリがこのアプリのサンドボックスを共有しています`,
      sharedDetail: (connection, app, others) =>
        `接続「${connection}」の厳格に分離されたアプリは、すべて同じアプリのサンドボックスの中にあります。ここに表示されるのは「${app}」と${others.map((o) => `「${o}」`).join("、")}を合わせたトラフィックで、アプリごとには分けられません。`,
      latestSecond: "直近 1 秒",
      trackedFlows: "追跡中のフロー",
      trackedFlowsHint: "パケットフィルターが追跡しているアプリ自身の接続。ポート転送経由の着信は含まれません",
      flowTable: "フローテーブル",
      flowTableHint: "この接続の現在の世代以降。応答のないフローから先に場所を譲ります",
      counted:
        "数えているのは、アプリが送受信する TCP と UDP のデータです。アプリ自身の接続（再送パケットも含む）と、ポート転送経由の着信接続が対象で、所属する接続のゲートウェイと DNS は含みません。これらはすべて接続のトラフィックに計上済みです。",
    },
  },
});
