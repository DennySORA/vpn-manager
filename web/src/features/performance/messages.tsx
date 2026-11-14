// Text of the Performance page (效能統計): the header, the trends' range and how fresh the analysis is, the views (程序,
// 連線, 線索) and the product summary that leads each of them, the processes, the connections and their Gateways, the
// bottleneck leads and the reference scale, the trends, and the words for the process roles and for the reason codes of
// unknown or qualified values. The leads' own sentences come from the service and are shown as they arrive. A .tsx: a
// few sentences carry markup (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** “1 connection”, “3 connections”. */
function countEn(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The space between Japanese text and a Latin letter or a digit after it (「開始は 3 分前」, 「開始はたった今」). */
function gapJa(text: string): string {
  return /^[A-Za-z0-9]/.test(text) ? " " : "";
}

export const m = defineMessages({
  en: {
    title: "Performance",
    description: "CPU and memory of each process, and the live state of each connection and Gateway.",
    help: "Passive observation only reads the per-second samples already kept and analyzes them every 5 seconds; it generates no speed-test traffic. Rates cover the last few seconds; latency, refusals and coverage cover the last few minutes. An unknown value shows “—” with its reason and is never taken as 0. The time range above applies to every trend chart.",
    helpText:
      "Reads only the samples already kept and analyzes them every 5 seconds, generating no traffic; an unknown value is never taken as 0.",
    loading: "Loading the performance summary",
    loadFailed: "Cannot get the performance summary",
    /** The trends' time ranges: a segment's label and its tooltip. */
    ranges: {
      "15m": { label: "15 min", long: "Last 15 minutes" },
      "1h": { label: "1 hour", long: "Last hour" },
      "6h": { label: "6 hours", long: "Last 6 hours" },
      "24h": { label: "24 hours", long: "Last 24 hours" },
      "7d": { label: "7 days", long: "Last 7 days" },
      "30d": { label: "30 days", long: "Last 30 days" },
    },
    toolStrip: {
      label: "Trend range",
      range: "Time range of the trends",
      /** How fresh the analysis is; `time` is the clock time of the latest one. */
      latest: (time: ReactNode): ReactNode => <>Analyzed every 5 s · latest {time}</>,
      reading: "Loading…",
    },
    stale: {
      /** `time`: when the analysis on screen was made. */
      refreshFailed: (time: string) => `Cannot refresh: showing the analysis from ${time}`,
      frozen: "The figures below stay at that analysis; they are not the current values.",
      outdated: (time: string) => `Data out of date: showing the analysis from ${time}`,
      /** Why the data is old: the core service is away, and/or the last analysis is `ageSeconds` old (null: it is not). */
      detail: (managerDown: boolean, ageSeconds: number | null): string => {
        const age =
          ageSeconds === null ? null : `${countEn(ageSeconds, "second", "seconds")} ago (it updates every 5 seconds)`;
        if (managerDown)
          return age
            ? `The core service (manager) is not connected: the last analysis was ${age}.`
            : "The core service (manager) is not connected: it updates by itself once the connection is back.";
        return age ? `The last analysis was ${age}.` : "It updates by itself once the connection is back.";
      },
    },
    views: {
      processes: "Processes",
      connections: "Connections",
      hints: "Leads",
      /** After the leads tab's count, for assistive technology. */
      hintsUnit: (count: number): string => (count === 1 ? "lead" : "leads"),
    },
    /** The selected connection (the URL's `instance`) is not in the analysis. */
    missing: {
      title: "This connection was not found",
      clear: "Clear selection",
      body: "It may have been deleted, or it has no performance data yet.",
    },
    /** The product's processes by role (the process names themselves stay as they are). */
    role: { manager: "manager", controller: "controller", worker: "connection worker" },
    /** A worker's generation (a connection's run counter). */
    generation: (generation: number) => `Generation ${generation}`,
    cpuCore: "CPU (% of one core)",
    /** Reason codes of unknown or qualified values, in words (the code is shown beside). */
    reason: {
      NOT_MEASURED: "Not measured yet",
      INSUFFICIENT_SAMPLES: "Too few samples: fewer than two consecutive samples, so no rate can be computed",
      INSTANCE_NOT_RUNNING: "The connection is not running",
      NEW_GENERATION: "A new worker took over within the window: the counts start over",
      COUNTER_RESET: "The counter went backwards or the clock did not advance: no rate for this stretch",
      LONG_INTERVAL: "Two samples are too far apart: the rate in between is unknown",
      OVERFLOW_BUCKET: "Falls in the last bucket, which has no upper bound",
      NO_LATENCY_SAMPLES: "No latency samples in the window",
      NOT_REPORTED: "This process or platform does not report it",
      NOT_APPLICABLE: "Does not apply to this scope",
      NOT_REFERENCE_ENVIRONMENT: "This host is not the specification's reference environment (8 logical CPUs, 16 GiB)",
      NOT_IDLE: "Idle CPU is not judged while there is data traffic",
    },
    value: {
      /** An unknown value's tooltip: the reason in words, then its code. */
      reasonWithCode: (reason: string, code: string) => `${reason} (${code})`,
      /** Read after the dash of an unknown value. */
      srReason: (reason: string) => `: ${reason}`,
    },
    latency: {
      noSamples: "No samples",
      /** The tooltip of p50／p95／p99: each one's bucket, how many were measured and how many timed out. */
      buckets: (p50: string, p95: string, p99: string, count: string, timeouts: string) =>
        `Buckets (lower–upper bound): p50 ${p50}; p95 ${p95}; p99 ${p99}; ${count} ${count === "1" ? "measurement" : "measurements"}, ${timeouts} timed out`,
    },
    summary: {
      label: "Product summary",
      cpu: "Product CPU (% of one core)",
      /** Under the product's CPU: its share of the whole host (`host`), of `count` logical CPUs (`cpus`). */
      cpuHost: (host: ReactNode, cpus: ReactNode, count: number): ReactNode => (
        <>
          Whole host {host} ({cpus} logical {count === 1 ? "CPU" : "CPUs"})
        </>
      ),
      rss: "Product memory RSS (summed)",
      sharedPages: "Shared pages are counted more than once",
      processes: "Product processes",
      processRoles: "manager, controller and each connection's worker",
      flows: "Data / probe / control flows",
      flowsApart: "Probe and control flows are counted separately",
      collecting: "Collecting",
      /** `since`: when the manager started collecting, relative (“3 minutes ago”). */
      collectingDetail: (since: string, minutes: number, secondsLeft: number) =>
        `The manager started collecting ${since}; the ${minutes}-minute window of latency and counter differences is complete in about ${countEn(secondsLeft, "second", "seconds")}, and until then the figures cover a shorter time.`,
      partial: "Partial data",
      /** Gateways left out of the answer, and running connections whose sampling has gaps. */
      partialDetail: (omittedGateways: number, lowCoverage: number): string => {
        const omitted = !omittedGateways
          ? ""
          : omittedGateways === 1
            ? "1 Gateway exceeds the size limit of a single response and is not listed (its connection's total still includes it)."
            : `${omittedGateways} Gateways exceed the size limit of a single response and are not listed one by one (their connections' totals still include them).`;
        const low = lowCoverage
          ? `${countEn(lowCoverage, "connection has", "connections have")} a sampling coverage below 99 %: there are gaps, and gaps are not filled with 0.`
          : "";
        return [omitted, low].filter((s) => s !== "").join(" ");
      },
    },
    processes: {
      title: "Processes",
      description: (secs: number) =>
        `Sampled every ${countEn(secs, "second", "seconds")}; a process is identified by its pid plus its start time, not by the pid alone. RSS is summed over the processes, so shared pages are counted more than once.`,
      table: "CPU and memory by role",
      role: "Role",
      count: "Processes",
      cpuHost: "CPU (% of host)",
      peakRss: "Sampled peak RSS",
      total: "Product total",
      each: (count: number) => `Individual processes (${count})`,
      eachLabel: "Individual processes",
    },
    hints: {
      title: "Bottleneck leads",
      description: "Inferred from the current figures, not measured causes",
      /** The tag on each lead. */
      inferred: "Inferred",
      none: "Nothing worth noting right now (flow limits, memory budget, worker CPU, refusals, timeouts and underlay packets are all within their thresholds, or there is no data yet).",
    },
    reference: {
      title: "Reference scale: 5 / 10 / 500",
      description: "The specification's reference workload: neither a live value nor a product limit",
      scale: "Reference scale",
      workload: (instances: number, gateways: number, flows: number) =>
        `${countEn(instances, "connection", "connections")}, ${countEn(gateways, "Gateway", "Gateways")}, ${countEn(flows, "concurrent data flow", "concurrent data flows")}`,
      perUnit: (gatewaysPerInstance: number, flowsPerGateway: number) =>
        `${countEn(gatewaysPerInstance, "Gateway", "Gateways")} per connection, ${countEn(flowsPerGateway, "flow", "flows")} per Gateway`,
      now: "Now",
      /** What runs now; each figure is already an element. */
      current: (ready: ReactNode, serving: ReactNode, flows: ReactNode): ReactNode => (
        <>
          Ready connections {ready}, serving Gateways {serving}, data flows {flows}
        </>
      ),
      /** The ready connections with at least `gateways` Gateways serving: `count`. */
      eligible: (gateways: number, count: ReactNode): ReactNode => (
        <>
          Ready connections with at least {countEn(gateways, "Gateway", "Gateways")} serving: {count}
        </>
      ),
    },
    connections: {
      title: "Connections and Gateways",
      description: (rateSecs: number, latencyMinutes: number) =>
        `Rates are over the last ${countEn(rateSecs, "second", "seconds")}; latency (p50 / p95 / p99, bucket upper bounds), refusals and coverage over the last ${countEn(latencyMinutes, "minute", "minutes")}. No traffic does not mean low capacity.`,
      empty: "No connections yet",
      emptyBody:
        "Passive observation still measures the manager and the controller themselves; once a connection is created and started, the rates, traffic and latency of each connection and Gateway are listed here.",
      /** The table's column headings and the line under some of them. */
      columns: {
        connection: "Connection",
        dataFlows: "Data flows",
        tcpUdp: "TCP / UDP",
        probeControl: "Probe / control",
        refused: "Refused",
        latency: "Latency",
        quantiles: "p50 / p95 / p99",
        coverage: "Coverage",
        cpuRss: "CPU / RSS",
      },
      /** A Gateway has no WireGuard figures of its own. */
      notApplicable: "Not applicable",
      /** A Gateway's maximum number of connections. */
      limit: (max: number) => `Limit ${max}`,
      /** The connect latency, beside the DNS one. */
      connect: "Connect",
      /** Connects that failed; `notFound` of them for a name that does not exist (null: none). */
      failures: (failures: string, notFound: string | null) =>
        `Failed ${failures}${notFound === null ? "" : ` (name not found: ${notFound})`}`,
      /** A Gateway's CPU and memory are its connection's. */
      countedInConnection: "Counted in connection",
      expandGatewaysOf: (name: string) => `Expand the Gateways of “${name}”`,
      collapseGatewaysOf: (name: string) => `Collapse the Gateways of “${name}”`,
      expandGateways: "Expand Gateways",
      collapseGateways: "Collapse Gateways",
      /** WireGuard's two directions. */
      receive: "Receive",
      send: "Send",
      /** The connection's TCP capacity; `value` is already an element. */
      capacity: (value: ReactNode): ReactNode => <>Capacity {value}</>,
      capacityByMemory: "The TCP capacity is limited by this connection's memory budget",
      byMemory: "Limited by the memory budget",
      underlayBlocked: (count: string) => `Blocked by the underlay: ${count}`,
      /** How long the sampling of the window is missing. */
      missing: (secs: number) => `${secs} s missing`,
      noGateways: "No Gateways enabled.",
      footer:
        "Select a connection to see its trends (↑ / ↓ for another); data flows are the TCP connections and UDP associations that applications open through Gateways, and probe and control flows (DNS, health probes, Provider) are counted separately, not as data flows.",
    },
    trends: {
      /** A chart's accessible name: its title, then how to read it. */
      chartLabel: (title: string) =>
        `${title}; use the left and right arrow keys to read the values point by point, or open the table`,
      empty: "No data for this period",
      loading: "Loading trends",
      productTotal: "Total of all processes",
      roles: "Resource trends (by role)",
      /** One point every `secs`; with `sharedPages`, RSS is a sum that counts shared pages more than once. */
      resolution: (secs: number, sharedPages: boolean) =>
        `One point every ${countEn(secs, "second", "seconds")}; gaps are left blank, not filled with 0.${sharedPages ? " RSS is summed over the processes, so shared pages are counted more than once." : ""}`,
      stored: "Process CPU and memory are stored every 5 seconds: raw for 24 hours, per minute for 30 days",
      metric: "Metric",
      memory: "Memory RSS",
      /** A chart's share of the range with samples, in percent. */
      coverage: (percent: string) => `Coverage ${percent} %`,
      of: (name: string) => `Trends of “${name}”`,
      payloadNote:
        "Payload is the bytes applications see (without the SOCKS / HTTP handshake); it cannot be added to WireGuard bytes.",
      history: "History",
      toConnection: "Go to connection",
      close: (name: string) => `Close the trends of “${name}”`,
      payloadRate: "Payload rate",
      workerCpu: "worker CPU (% of one core)",
    },
  },
  "zh-TW": {
    title: "效能統計",
    description: "各程序的 CPU 與記憶體、各連線與代理埠的即時狀態。",
    help: "被動觀測只讀現有的每秒樣本，每 5 秒分析一次，不產生任何測速流量。速率看最近幾秒，延遲、拒絕數與涵蓋率看最近幾分鐘；未知的值顯示「—」並說明原因，不當成 0。上方的時間範圍套用到所有趨勢圖。",
    helpText: "只讀現有樣本、每 5 秒分析，不產生任何流量；未知的值不當成 0。",
    loading: "載入效能摘要",
    loadFailed: "無法取得效能摘要",
    ranges: {
      "15m": { label: "15 分鐘", long: "過去 15 分鐘" },
      "1h": { label: "1 小時", long: "過去 1 小時" },
      "6h": { label: "6 小時", long: "過去 6 小時" },
      "24h": { label: "24 小時", long: "過去 24 小時" },
      "7d": { label: "7 天", long: "過去 7 天" },
      "30d": { label: "30 天", long: "過去 30 天" },
    },
    toolStrip: {
      label: "趨勢範圍",
      range: "趨勢的時間範圍",
      latest: (time) => <>每 5 秒分析 · 最近一次 {time}</>,
      reading: "讀取中…",
    },
    stale: {
      refreshFailed: (time) => `無法更新：顯示的是 ${time} 的分析`,
      frozen: "下面的數字停在那一次分析，不是現在的值。",
      outdated: (time) => `資料過時：顯示的是 ${time} 的分析`,
      detail: (managerDown, ageSeconds) =>
        `${managerDown ? "核心服務（manager）未連線：" : ""}${ageSeconds !== null ? `最後一次分析是 ${ageSeconds} 秒前（每 5 秒更新一次）。` : "恢復連線後會自動更新。"}`,
    },
    views: {
      processes: "程序",
      connections: "連線",
      hints: "線索",
      hintsUnit: () => "條線索",
    },
    missing: {
      title: "找不到這條連線",
      clear: "清除選取",
      body: "它可能已被刪除，或還沒有效能數據。",
    },
    role: { manager: "manager", controller: "controller", worker: "連線 worker" },
    generation: (generation) => `第 ${generation} 代`,
    cpuCore: "CPU（單核 %）",
    reason: {
      NOT_MEASURED: "尚未量測",
      INSUFFICIENT_SAMPLES: "樣本不足：少於兩個連續樣本，無法算速率",
      INSTANCE_NOT_RUNNING: "連線沒有在執行",
      NEW_GENERATION: "視窗內換了新的 worker：計數重新開始",
      COUNTER_RESET: "計數器倒退或時鐘沒有前進：這段不算速率",
      LONG_INTERVAL: "兩個樣本相隔太久：中間的速率未知",
      OVERFLOW_BUCKET: "落在最後一個區間，沒有上界",
      NO_LATENCY_SAMPLES: "視窗內沒有延遲樣本",
      NOT_REPORTED: "這個程序或平台不回報",
      NOT_APPLICABLE: "這個範圍不適用",
      NOT_REFERENCE_ENVIRONMENT: "這台主機不是規格的參考環境（8 個邏輯 CPU、16 GiB）",
      NOT_IDLE: "有資料流量時不判定閒置 CPU",
    },
    value: {
      reasonWithCode: (reason, code) => `${reason}（${code}）`,
      srReason: (reason) => `：${reason}`,
    },
    latency: {
      noSamples: "無樣本",
      buckets: (p50, p95, p99, count, timeouts) =>
        `區間（下界–上界）：p50 ${p50}；p95 ${p95}；p99 ${p99}；${count} 次，逾時 ${timeouts} 次`,
    },
    summary: {
      label: "產品摘要",
      cpu: "產品 CPU（單核 %）",
      cpuHost: (host, cpus) => (
        <>
          整機 {host}（{cpus} 個邏輯 CPU）
        </>
      ),
      rss: "產品記憶體 RSS（相加）",
      sharedPages: "共用頁面會重複計算",
      processes: "產品程序",
      processRoles: "manager、controller、各連線 worker",
      flows: "資料／探測／控制流量",
      flowsApart: "探測與控制流量分開計",
      collecting: "收集中",
      collectingDetail: (since, minutes, secondsLeft) =>
        `manager 在 ${since}開始收集；延遲與計數差值的 ${minutes} 分鐘視窗還要約 ${secondsLeft} 秒才完整，之前的數字涵蓋較短時間。`,
      partial: "部分資料",
      partialDetail: (omittedGateways, lowCoverage) =>
        `${omittedGateways ? `有 ${omittedGateways} 個代理埠超過單次回應上限，沒有逐一列出（所屬連線的合計仍包含它們）。` : ""}${lowCoverage ? `${lowCoverage} 條連線的取樣涵蓋率低於 99 %：中間有缺口，缺口不補 0。` : ""}`,
    },
    processes: {
      title: "程序",
      description: (secs) =>
        `每 ${secs} 秒取樣；程序以 pid＋啟動時間識別，不只看 pid。RSS 為各程序相加，共用頁面會重複計算。`,
      table: "各角色的 CPU 與記憶體",
      role: "角色",
      count: "程序",
      cpuHost: "CPU（整機 %）",
      peakRss: "取樣峰值 RSS",
      total: "產品合計",
      each: (count) => `逐一程序（${count}）`,
      eachLabel: "逐一程序",
    },
    hints: {
      title: "瓶頸線索",
      description: "依目前數字推論，不是量到的原因",
      inferred: "推論",
      none: "目前沒有值得注意的跡象（流量上限、記憶體預算、worker CPU、拒絕、逾時、底層封包都在門檻內，或尚無資料）。",
    },
    reference: {
      title: "參考規模：5／10／500",
      description: "規格的參考工作量，不是即時值，也不是產品上限",
      scale: "參考規模",
      workload: (instances, gateways, flows) => `${instances} 條連線、${gateways} 個代理埠、${flows} 條並行資料流量`,
      perUnit: (gatewaysPerInstance, flowsPerGateway) =>
        `每條連線 ${gatewaysPerInstance} 個代理埠，每個代理埠 ${flowsPerGateway} 條`,
      now: "現在",
      current: (ready, serving, flows) => (
        <>
          就緒連線 {ready}、服務中的代理埠 {serving}、資料流量 {flows}
        </>
      ),
      eligible: (gateways, count) => (
        <>
          就緒且至少 {gateways} 個代理埠在服務的連線：{count}
        </>
      ),
    },
    connections: {
      title: "連線與代理埠",
      description: (rateSecs, latencyMinutes) =>
        `速率看最近 ${rateSecs} 秒；延遲（p50／p95／p99，bucket 上界）、拒絕數與涵蓋率看最近 ${latencyMinutes} 分鐘。沒有流量不代表容量低。`,
      empty: "還沒有連線",
      emptyBody:
        "被動觀測照常量測 manager 與 controller 自己；建立並啟動連線後，這裡會列出每條連線與代理埠的速率、流量與延遲。",
      columns: {
        connection: "連線",
        dataFlows: "資料流量",
        tcpUdp: "TCP／UDP",
        probeControl: "探測／控制",
        refused: "拒絕",
        latency: "延遲",
        quantiles: "p50／p95／p99",
        coverage: "涵蓋率",
        cpuRss: "CPU／RSS",
      },
      notApplicable: "不適用",
      limit: (max) => `上限 ${max}`,
      connect: "連線",
      failures: (failures, notFound) => `失敗 ${failures}${notFound === null ? "" : `（名稱不存在 ${notFound}）`}`,
      countedInConnection: "算在連線",
      expandGatewaysOf: (name) => `展開「${name}」的代理埠`,
      collapseGatewaysOf: (name) => `收合「${name}」的代理埠`,
      expandGateways: "展開代理埠",
      collapseGateways: "收合代理埠",
      receive: "收",
      send: "送",
      capacity: (value) => <>容量 {value}</>,
      capacityByMemory: "TCP 連線容量受這條連線的記憶體預算限制",
      byMemory: "受記憶體預算限制",
      underlayBlocked: (count) => `底層擋下 ${count}`,
      missing: (secs) => `缺 ${secs} 秒`,
      noGateways: "沒有啟用的代理埠。",
      footer:
        "選一條連線看它的趨勢（↑／↓ 換一條）；資料流量是應用程式經代理埠開的 TCP 連線與 UDP association，探測與控制流量（DNS、健康探測、Provider）分開計，不算在資料流量內。",
    },
    trends: {
      chartLabel: (title) => `${title}；用左右鍵逐點查看數值，或開啟表格`,
      empty: "這段時間沒有資料",
      loading: "載入趨勢",
      productTotal: "產品合計（manager＋controller＋worker）",
      roles: "資源趨勢（依角色）",
      resolution: (secs, sharedPages) =>
        `每 ${secs} 秒一點；缺口留白、不補 0。${sharedPages ? "RSS 為各程序相加，共用頁面會重複計算。" : ""}`,
      stored: "程序 CPU 與記憶體每 5 秒保存一次：原始 24 小時、每分鐘 30 天",
      metric: "指標",
      memory: "記憶體 RSS",
      coverage: (percent) => `涵蓋 ${percent} %`,
      of: (name) => `「${name}」的趨勢`,
      payloadNote: "Payload 是應用程式看到的位元組（不含 SOCKS／HTTP 交握），與 WireGuard 位元組不能相加。",
      history: "歷史數據",
      toConnection: "前往連線",
      close: (name) => `關閉「${name}」的趨勢`,
      payloadRate: "Payload 速率",
      workerCpu: "worker CPU（單核 %）",
    },
  },
  ja: {
    title: "パフォーマンス",
    description: "各プロセスの CPU とメモリ、各接続とゲートウェイのリアルタイムの状態。",
    help: "パッシブ観測は保存済みの毎秒のサンプルを読むだけで、5 秒ごとに分析し、速度測定のトラフィックは一切発生させません。速度は直近数秒、遅延、拒否数、カバー率は直近数分を対象にします。不明な値は「—」と表示して理由を示し、0 とはみなしません。上の時間範囲はすべての推移グラフに適用されます。",
    helpText:
      "保存済みのサンプルを読むだけで 5 秒ごとに分析し、トラフィックは発生させません。不明な値は 0 とみなしません。",
    loading: "パフォーマンスの概要を読み込み中",
    loadFailed: "パフォーマンスの概要を取得できません",
    ranges: {
      "15m": { label: "15 分", long: "過去 15 分間" },
      "1h": { label: "1 時間", long: "過去 1 時間" },
      "6h": { label: "6 時間", long: "過去 6 時間" },
      "24h": { label: "24 時間", long: "過去 24 時間" },
      "7d": { label: "7 日", long: "過去 7 日間" },
      "30d": { label: "30 日", long: "過去 30 日間" },
    },
    toolStrip: {
      label: "推移の範囲",
      range: "推移の時間範囲",
      latest: (time) => <>5 秒ごとに分析 · 最新 {time}</>,
      reading: "読み込み中…",
    },
    stale: {
      refreshFailed: (time) => `更新できません：${time} 時点の分析を表示しています`,
      frozen: "以下の数値はその時点の分析のもので、現在の値ではありません。",
      outdated: (time) => `データが古くなっています：${time} 時点の分析を表示しています`,
      detail: (managerDown, ageSeconds) =>
        `${managerDown ? "コアサービス（manager）に未接続：" : ""}${ageSeconds !== null ? `最後の分析は ${ageSeconds} 秒前です（5 秒ごとに更新）。` : "接続が回復すると自動的に更新されます。"}`,
    },
    views: {
      processes: "プロセス",
      connections: "接続",
      hints: "手がかり",
      hintsUnit: () => "件の手がかり",
    },
    missing: {
      title: "この接続が見つかりません",
      clear: "選択を解除",
      body: "削除されたか、まだパフォーマンスのデータがない可能性があります。",
    },
    role: { manager: "manager", controller: "controller", worker: "接続 worker" },
    generation: (generation) => `第 ${generation} 世代`,
    cpuCore: "CPU（1 コア基準 %）",
    reason: {
      NOT_MEASURED: "未測定",
      INSUFFICIENT_SAMPLES: "サンプル不足：連続したサンプルが 2 つ未満のため、速度を計算できません",
      INSTANCE_NOT_RUNNING: "接続が実行されていません",
      NEW_GENERATION: "ウィンドウ内で新しい worker に切り替わりました：カウントは最初からです",
      COUNTER_RESET: "カウンターが戻ったか、時計が進んでいません：この区間の速度は計算しません",
      LONG_INTERVAL: "2 つのサンプルの間隔が長すぎます：その間の速度は不明です",
      OVERFLOW_BUCKET: "最後の区間に入っており、上限がありません",
      NO_LATENCY_SAMPLES: "ウィンドウ内に遅延のサンプルがありません",
      NOT_REPORTED: "このプロセスまたはプラットフォームは報告しません",
      NOT_APPLICABLE: "この範囲には該当しません",
      NOT_REFERENCE_ENVIRONMENT: "このホストは仕様の参考環境（論理 CPU 8 個、16 GiB）ではありません",
      NOT_IDLE: "データのトラフィックがある間は、アイドル時の CPU を判定しません",
    },
    value: {
      reasonWithCode: (reason, code) => `${reason}（${code}）`,
      srReason: (reason) => `：${reason}`,
    },
    latency: {
      noSamples: "サンプルなし",
      buckets: (p50, p95, p99, count, timeouts) =>
        `区間（下限–上限）：p50 ${p50}、p95 ${p95}、p99 ${p99}、${count} 回、タイムアウト ${timeouts} 回`,
    },
    summary: {
      label: "全体の概要",
      cpu: "全体の CPU（1 コア基準 %）",
      cpuHost: (host, cpus) => (
        <>
          ホスト全体 {host}（論理 CPU {cpus} 個）
        </>
      ),
      rss: "全体のメモリ RSS（合計）",
      sharedPages: "共有ページは重複して数えられます",
      processes: "VPN Manager のプロセス",
      processRoles: "manager、controller、各接続の worker",
      flows: "データ／プローブ／制御フロー",
      flowsApart: "プローブと制御のフローは別に数えます",
      collecting: "収集中",
      collectingDetail: (since, minutes, secondsLeft) =>
        `manager の収集開始は${gapJa(since)}${since}です。遅延とカウンター差分の ${minutes} 分間のウィンドウがそろうまであと約 ${secondsLeft} 秒かかり、それまでの数値はより短い時間を対象にしています。`,
      partial: "一部のデータ",
      partialDetail: (omittedGateways, lowCoverage) =>
        `${omittedGateways ? `${omittedGateways} 件のゲートウェイは 1 回の応答の上限を超えるため、個別には表示していません（所属する接続の合計には含まれています）。` : ""}${lowCoverage ? `${lowCoverage} 件の接続はサンプリングのカバー率が 99 % 未満です。途中に欠落があり、欠落は 0 で埋めません。` : ""}`,
    },
    processes: {
      title: "プロセス",
      description: (secs) =>
        `${secs} 秒ごとにサンプリングします。プロセスは pid だけでなく、pid＋起動時刻で識別します。RSS は各プロセスの合計で、共有ページは重複して数えられます。`,
      table: "役割別の CPU とメモリ",
      role: "役割",
      count: "プロセス",
      cpuHost: "CPU（ホスト全体 %）",
      peakRss: "サンプル中のピーク RSS",
      total: "全体の合計",
      each: (count) => `個別のプロセス（${count}）`,
      eachLabel: "個別のプロセス",
    },
    hints: {
      title: "ボトルネックの手がかり",
      description: "現在の数値からの推論で、測定された原因ではありません",
      inferred: "推論",
      none: "現在、注意すべき兆候はありません（フロー上限、メモリ予算、worker CPU、拒否、タイムアウト、アンダーレイのパケットがすべてしきい値内か、まだデータがありません）。",
    },
    reference: {
      title: "参考規模：5／10／500",
      description: "仕様上の参考となる作業量で、リアルタイムの値でも製品の上限でもありません",
      scale: "参考規模",
      workload: (instances, gateways, flows) =>
        `${instances} 件の接続、${gateways} 件のゲートウェイ、${flows} 件の同時データフロー`,
      perUnit: (gatewaysPerInstance, flowsPerGateway) =>
        `接続ごとに ${gatewaysPerInstance} 件のゲートウェイ、ゲートウェイごとに ${flowsPerGateway} 件`,
      now: "現在",
      current: (ready, serving, flows) => (
        <>
          準備完了の接続 {ready}、稼働中のゲートウェイ {serving}、データフロー {flows}
        </>
      ),
      eligible: (gateways, count) => (
        <>
          準備完了で、稼働中のゲートウェイが {gateways} 件以上ある接続：{count}
        </>
      ),
    },
    connections: {
      title: "接続とゲートウェイ",
      description: (rateSecs, latencyMinutes) =>
        `速度は直近 ${rateSecs} 秒間、遅延（p50／p95／p99、バケットの上限）、拒否数、カバー率は直近 ${latencyMinutes} 分間の値です。トラフィックがなくても容量が少ないとは限りません。`,
      empty: "まだ接続がありません",
      emptyBody:
        "パッシブ観測では manager と controller 自身は通常どおり測定します。接続を作成して開始すると、各接続とゲートウェイの速度、トラフィック、遅延がここに表示されます。",
      columns: {
        connection: "接続",
        dataFlows: "データフロー",
        tcpUdp: "TCP／UDP",
        probeControl: "プローブ／制御",
        refused: "拒否",
        latency: "遅延",
        quantiles: "p50／p95／p99",
        coverage: "カバー率",
        cpuRss: "CPU／RSS",
      },
      notApplicable: "該当なし",
      limit: (max) => `上限 ${max}`,
      connect: "接続",
      failures: (failures, notFound) =>
        `失敗 ${failures}${notFound === null ? "" : `（名前が見つからない ${notFound}）`}`,
      countedInConnection: "接続に計上",
      expandGatewaysOf: (name) => `「${name}」のゲートウェイを開く`,
      collapseGatewaysOf: (name) => `「${name}」のゲートウェイを閉じる`,
      expandGateways: "ゲートウェイを開く",
      collapseGateways: "ゲートウェイを閉じる",
      receive: "受信",
      send: "送信",
      capacity: (value) => <>容量 {value}</>,
      capacityByMemory: "TCP の容量はこの接続のメモリ予算で制限されています",
      byMemory: "メモリ予算による制限",
      underlayBlocked: (count) => `アンダーレイで遮断 ${count}`,
      missing: (secs) => `${secs} 秒欠落`,
      noGateways: "有効なゲートウェイはありません。",
      footer:
        "接続を選ぶとその推移を表示します（↑／↓ で切り替え）。データフローはアプリケーションがゲートウェイ経由で開く TCP 接続と UDP アソシエーションで、プローブと制御のフロー（DNS、ヘルスチェック、Provider）は別に数え、データフローには含めません。",
    },
    trends: {
      chartLabel: (title) => `${title}。左右キーで 1 点ずつ値を確認するか、表を開きます`,
      empty: "この期間のデータはありません",
      loading: "推移を読み込み中",
      productTotal: "全プロセスの合計",
      roles: "リソースの推移（役割別）",
      resolution: (secs, sharedPages) =>
        `${secs} 秒ごとに 1 点。欠落は空白のままにし、0 で埋めません。${sharedPages ? "RSS は各プロセスの合計で、共有ページは重複して数えられます。" : ""}`,
      stored: "プロセスの CPU とメモリは 5 秒ごとに保存：生データは 24 時間、1 分ごとの値は 30 日間",
      metric: "指標",
      memory: "メモリ RSS",
      coverage: (percent) => `カバー率 ${percent} %`,
      of: (name) => `「${name}」の推移`,
      payloadNote:
        "Payload はアプリケーションから見たバイト数（SOCKS／HTTP のハンドシェイクを含まない）で、WireGuard のバイト数とは足し合わせられません。",
      history: "履歴データ",
      toConnection: "接続へ移動",
      close: (name) => `「${name}」の推移を閉じる`,
      payloadRate: "Payload 速度",
      workerCpu: "worker CPU（1 コア基準 %）",
    },
  },
});
