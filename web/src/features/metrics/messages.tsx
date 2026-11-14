// Text of 數據統計 (/metrics): the page, its tool strip and views, the words model.ts writes about ranges, scopes,
// resolutions, gaps and values (the overview and the performance page show some of them too), the recording notice,
// the summary of a range and the per-connection breakdown. The chart cards have their own table (charts/messages.ts),
// and so has the retention view (retention/messages.ts). 下載, 上傳, 未知, 沒有資料, 原因未知 and 操作 are the shared
// words (components/ui/messages.ts, `common`).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** The data directory's free space, and the free space from which normal storage resumes (both formatted). */
interface FreeSpace {
  free: string;
  resume: string;
}

export const m = defineMessages({
  en: {
    title: "Metrics",
    description: "Stored traffic, connection counts, DNS, latency and worker resources.",
    help: "Every figure states its range and the time it covers. Time without data is left blank, with the reason in the gap legend, and a restart is marked with a vertical line. Focus a chart and use ←/→ to step through its points (the charts of one tab share one cursor); every chart can also switch to a table. The range, scope, sort order and tab are all in the address.",
    helpText:
      "Time without data is left blank, with the reason; step through a chart with ←/→, or switch it to a table.",
    views: {
      traffic: "Traffic",
      latency: "Latency and DNS",
      resources: "Resources",
      breakdown: "By connection",
      retention: "Retention",
    },
    /** The tool strip: the range, the scope, the resolution and how fresh the data is. */
    toolStrip: "Data range",
    timeRange: "Time range",
    /** The ranges' names on the segmented control, and as a phrase. */
    ranges: {
      minutes: (n: number) => `${n} min`,
      hours: (n: number): string => (n === 1 ? "1 hour" : `${n} hours`),
      days: (n: number): string => (n === 1 ? "1 day" : `${n} days`),
      lastMinutes: (n: number): string => (n === 1 ? "Last minute" : `Last ${n} minutes`),
      lastHours: (n: number): string => (n === 1 ? "Last hour" : `Last ${n} hours`),
      lastDays: (n: number): string => (n === 1 ? "Last day" : `Last ${n} days`),
    },
    /** What the page shows: every connection, one connection or one Gateway. */
    scope: {
      label: "Scope",
      current: (label: string) => `Scope: ${label}`,
      all: "All connections",
      connections: "Connections",
      gateways: "Gateways",
      /** A connection or a Gateway by its short ID, when it is not configured. */
      connectionId: (id: string) => `Connection ${id}`,
      gatewayId: (id: string) => `Gateway ${id}`,
      /** A Gateway with its port and its connection. */
      gateway: (name: string, port: number, owner: string | undefined) =>
        owner ? `${name} (:${port}, ${owner})` : `${name} (:${port})`,
      /** A scope that is no longer configured. */
      missing: (label: string) => `${label} (not found)`,
    },
    /** How much time one point of the charts stands for. */
    resolution: {
      seconds: (n: number) => `${n} s per point`,
      minutes: (n: number) => `${n} min per point`,
      hours: (n: number) => `${n} h per point`,
    },
    /** The same time, as what a peak is averaged over. */
    pointSpan: {
      seconds: (n: number): string => (n === 1 ? "1 second" : `${n} seconds`),
      minutes: (n: number): string => (n === 1 ? "1 minute" : `${n} minutes`),
      hours: (n: number): string => (n === 1 ? "1 hour" : `${n} hours`),
    },
    freshness: {
      updated: (resolution: string, when: string) => `${resolution} · updated ${when}`,
      reading: "Reading…",
    },
    stale: {
      title: (time: string) => `Cannot refresh: showing the data from ${time}`,
      detail: "The charts and totals stay as of the last successful read.",
    },
    loading: "Loading metrics",
    loadFailed: "Cannot load the metrics",
    /** What an empty chart says. */
    empty: {
      noConnections: "No connections yet, so no data",
      noData: "No data for this time (the connection was not running, or there are no samples yet)",
    },
    notFound: {
      title: "This connection or Gateway was not found",
      showAll: "Show all connections",
      detail: (failure: string) => `${failure}: it may have been deleted.`,
    },
    start: {
      title: "No connections yet",
      add: "Add connection",
      detail:
        "Once a connection exists and traffic goes through its Gateway, the history of traffic, connection counts, DNS and latency appears here.",
    },
    /** In place of the charts only a connection has, for one Gateway. */
    otherCharts: {
      label: "Other charts",
      detail:
        "WireGuard, DNS and the worker's resources belong to the whole connection; a Gateway has no such figures of its own.",
      viewOwner: (name: string) => `View its connection “${name}”`,
    },
    /** Why data is missing, by gap reason (the label of `missing` is the shared “No data”). */
    gaps: {
      missing: { detail: "The connection was not running, or nothing was recorded during this time" },
      new_generation: {
        label: "Restart",
        detail: "A new worker counts from 0 (the vertical line on the chart); its first sample has no rate yet",
      },
      long_interval: {
        label: "Samples too far apart",
        detail:
          "Two samples are more than 5 seconds apart (the host slept, for example), so the rate in between cannot be calculated",
      },
      counter_reset: {
        label: "Counter reset",
        detail: "A counter went backwards or the worker's clock did not advance; the rate of this span is unknown",
      },
      dropped: {
        label: "Dropped by the collector",
        detail: "Samples dropped while writing to the database was too slow",
      },
      quota: {
        label: "Deleted for the space limit",
        detail: "Data deleted early to stay within the metrics space limit",
      },
      disk_low: {
        label: "Low disk space",
        detail:
          "The disk of the data directory is low on space: to keep recording the newest data, the oldest data was deleted early (overwritten); only when even that left no room were the samples of this time not stored. Control data and secrets are not affected",
      },
      unavailable: {
        label: "Not reported",
        detail: "This host does not report the worker's CPU or memory readings",
      },
    },
    values: {
      /** Why a connect latency is unknown: nothing completed. */
      noneCompleted: "No completed connections",
      /** A latency in the open-ended bucket. */
      over: (limit: string) => `Over ${limit}`,
      /** After a failed-connect count: how many of them named a host that does not exist. */
      notFound: (n: string) => ` (name not found: ${n})`,
      /** The same, with the failures recorded before names were told apart. */
      notFoundUnclassified: (known: number, earlier: number) =>
        ` (name not found: ${known}; ${earlier} more not classified)`,
      noDnsQueries: "No DNS queries",
      perSecond: (rate: string) => `${rate}/s`,
      /** The newest window, which ends at the next sample. */
      openWindow: (start: string) => `From ${start} (still open)`,
    },
    duration: {
      seconds: (s: number) => `${s} s`,
      minutes: (min: number, s: number) => (s ? `${min} min ${s} s` : `${min} min`),
      hours: (h: number, min: number) => (min ? `${h} h ${min} min` : `${h} h`),
      days: (d: number, h: number) => (h ? `${d} d ${h} h` : `${d} d`),
    },
    /** How often something happened. */
    times: (n: number): string => (n === 1 ? "1 time" : `${n} times`),
    /** A relative time with the exact time after it. */
    when: (relative: string, absolute: string) => `${relative} (${absolute})`,
    noDataInRange: "No data in this range",
    availability: "Availability",
    /** Before the parts of a figure apart from ordinary proxy traffic. */
    ofWhich: "Of which",
    listSeparator: ", ",
    /** The parts of a connection's traffic apart from its ordinary proxy traffic. */
    parts: {
      sshDownloads: "SSH downloads",
      sshProxy: "SSH proxy",
      appSandbox: "App sandbox",
      /** The strict apps of a sandbox. */
      appNames: (names: readonly string[]) => names.join(", "),
    },
    /** An object that only has history left, by its short ID. */
    deleted: {
      connection: (id: string) => `Deleted connection (${id})`,
      gateway: (id: string) => `Deleted Gateway (${id})`,
    },
    /** The notice while recording is not as usual, and its line among the overview's items needing attention. */
    recording: {
      justNow: "just now",
      diskFull: "Disk full: the oldest records were overwritten",
      diskLow: "Low disk space: the oldest records were overwritten",
      failingTitle: "Metrics cannot be written",
      failingDetail: (since: string, error: string) =>
        `Since ${since}, new samples cannot be written to the metrics database: ${error}. Samples wait in a queue meanwhile (when it is full, the oldest are discarded and show as gaps on the charts); writing resumes by itself once it works again.`,
      failingAction: "View metric writes",
      /** `label` is the gap's name on the charts; `space` is null when the free space is not known. */
      overwriteDetail: (since: string, rows: number, label: string, lost: number, space: FreeSpace | null) => {
        const deleted = rows === 1 ? "the oldest record was" : `the ${rows} oldest records were`;
        const notStored =
          lost > 0
            ? ` Another ${lost === 1 ? "sample" : `${lost} samples`} did not fit even then and ${lost === 1 ? "was" : "were"} not stored.`
            : "";
        const resume = space
          ? ` The data directory has ${space.free} free; normal storage resumes once that is back above ${space.resume}.`
          : " Normal storage resumes once disk space is freed.";
        return `New data is still recorded. The metrics database no longer grows: since ${since}, ${deleted} deleted early to make room, marked “${label}” on the charts.${notStored}${resume}`;
      },
      overwriteAction: "View disk space",
      failingLine: (error: string) => `Metrics cannot be written: ${error}`,
      overwriteLine: (title: string) => `${title}. New data is still recorded.`,
    },
    summary: {
      label: "Range summary",
      /** The line above the figures: the scope, the range with its resolution, the time with data and its share. */
      header: (
        scope: ReactNode,
        range: string,
        resolution: string,
        covered: ReactNode,
        share: string,
        reporting: number | null,
      ): ReactNode => (
        <>
          {scope}
          {` · ${range} (${resolution}) · data for `}
          {covered}
          {` (${share})`}
          {reporting === null ? null : `, ${reporting} ${reporting === 1 ? "connection" : "connections"} reporting`}
        </>
      ),
      peakUnknown: "Peak unknown",
      /** The highest point of the chart, with what one point averages over. */
      peak: (rate: string, span: string) => `Peak ${rate} (average over ${span})`,
      partSize: (label: string, size: string) => `${label} ${size}`,
      downloadHint:
        "Data applications received through Gateways and port forwards, plus the TCP/UDP data the apps' own connections received inside the strictly isolated app sandbox (retransmitted packets count too). Only the counter differences between consecutive samples count; time without reports does not. Of this, SSH downloads are VPN Manager's SSH download jobs and SSH proxy is the SSH connections through Gateways (vpnctl ssh-proxy, port 22); the two do not overlap",
      connectLatency: "Connect latency p95",
      connects: (done: number | string, timeouts: number | string, failures: number | string, notFound: string) =>
        `Completed ${done} · timed out ${timeouts} · failed ${failures}${notFound}`,
      latencyHint:
        "The 95th percentile of proxy connects (resolving plus connecting), as the upper bound of its bucket; timeouts do not count as latency. Among the failures, “name not found” means DNS has no such name or no usable address, which is common for ad and tracking domains blocked by DNS or for names valid only on a local network; it is not a network fault. “Not classified” are failures recorded before they were told apart (before the upgrade)",
      dnsFailureRate: "DNS failure rate",
      dns: (queries: number | string, cacheHits: number | string, upstreamP95: string) =>
        `Queries ${queries} · cached ${cacheHits} · upstream p95 ${upstreamP95}`,
      gatewayDns: "A Gateway has no DNS of its own: see its connection",
      wireguardReceived: "WireGuard received",
      wireguardSent: (sent: string) => `Sent ${sent}; encrypted packets, which cannot be added to the traffic`,
      gateUnknown: "The gate state was not recorded for part of the time",
      /** `unrecorded` is null when the whole range was recorded. */
      availabilityDetail: (recorded: string, serving: string, unrecorded: string | null) =>
        `Accepted connections for ${serving} of the ${recorded} recorded${unrecorded === null ? "" : `; the other ${unrecorded} were not recorded and do not count`}`,
      availabilityHint:
        "The share of the recorded time during which the gate was open (accepting new connections). Time without records (not running, host asleep, or before recording began) counts as neither available nor unavailable",
      gapLegend: "Gap legend",
      spans: (n: number, duration: string) => `${n} ${n === 1 ? "span" : "spans"} · ${duration}`,
      truncated: "Too many gaps: only the first 2000 are listed; blank parts of the charts still mean unknown.",
    },
    breakdown: {
      columns: {
        rx: { hint: "Data applications received (counter differences between consecutive samples)" },
        tx: { hint: "Data applications sent" },
        peak: { label: "Peak download", hint: "The highest point of download on the chart (each point an average)" },
        p95: {
          label: "p95 connect latency",
          hint: "The 95th percentile of proxy connects (the upper bound of its bucket)",
        },
        avail: {
          hint: "The share of the recorded time spent accepting connections; below, the share of the range that was recorded",
        },
      },
      /** What assistive technology reads after a column heading. */
      sortBy: (label: string) => `, sort by ${label}`,
      notThroughProxy: "Not through the proxy",
      inGateway: "Counted in the Gateway",
      sameAsConnection: "Same as its connection",
      /** The share of the range that was recorded. */
      coverage: (share: string) => `Data ${share}`,
      /** A row's second line. */
      rows: {
        gateway: (port: string | null, withoutSsh: boolean | undefined) =>
          `Gateway${port ? ` ${port}` : ""}${withoutSsh ? " · SSH excluded" : ""}`,
        sandboxApps: (apps: string) => `Strict isolation: ${apps}`,
        sandbox: "Strictly isolated apps",
        pull: "SSH download jobs, through this connection's Gateways",
        ssh: "SSH connections (vpnctl ssh-proxy, port 22), through this connection's Gateways",
        connection: "Connection",
      },
      /** Why a row cannot narrow the page. */
      deleted: "Deleted: only this range's totals remain",
      showing: "The page is showing this object",
      showingOwner: (name: string) => `The page is showing its connection; the traffic of ${name} is in its charts`,
      chartsOf: (name: string) => `Show only the charts of “${name}”`,
      chartsOfOwner: (owner: string, part: string) => `Show only the charts of “${owner}” (including ${part})`,
      /** The parts of the table's title (a list). */
      titleParts: {
        connections: "Connections",
        gateways: "Gateways",
        sandboxes: "App sandboxes",
      },
      hint: (truncated: boolean) =>
        `Totals of the same range; sort by a column heading${truncated ? ". Too many items: only the first 128 connections and 128 Gateways are listed (the totals above still include them all)" : ""}`,
      tableLabel: (title: string) => `${title}: traffic, latency and availability in this range`,
      nameColumn: (ssh: boolean, sandboxes: boolean) =>
        `Connection / Gateway${ssh ? " / SSH" : ""}${sandboxes ? " / App sandbox" : ""}`,
      empty: "No connections or Gateways in this range",
    },
  },
  "zh-TW": {
    title: "數據統計",
    description: "已保存的流量、連線數、DNS、延遲與 worker 資源。",
    help: "每個數值都標明範圍與涵蓋時間；沒有資料的時間留白，原因寫在缺口說明，重新啟動以直線標出。圖可以聚焦後用 ←／→ 逐點查看（同一個分頁的圖共用同一條游標），每張圖也能切換成表格。範圍、對象、排序與分頁都在網址裡。",
    helpText: "沒有資料的時間留白並說明原因；圖可用 ←／→ 逐點查看，也能切換成表格。",
    views: {
      traffic: "流量",
      latency: "延遲與 DNS",
      resources: "資源",
      breakdown: "各連線",
      retention: "保存",
    },
    toolStrip: "數據範圍",
    timeRange: "時間範圍",
    ranges: {
      minutes: (n) => `${n} 分鐘`,
      hours: (n) => `${n} 小時`,
      days: (n) => `${n} 天`,
      lastMinutes: (n) => `過去 ${n} 分鐘`,
      lastHours: (n) => `過去 ${n} 小時`,
      lastDays: (n) => `過去 ${n} 天`,
    },
    scope: {
      label: "對象",
      current: (label) => `對象：${label}`,
      all: "全部連線",
      connections: "連線",
      gateways: "代理埠",
      connectionId: (id) => `連線 ${id}`,
      gatewayId: (id) => `代理埠 ${id}`,
      gateway: (name, port, owner) => `${name}（:${port}${owner ? `，${owner}` : ""}）`,
      missing: (label) => `${label}（找不到）`,
    },
    resolution: {
      seconds: (n) => `每點 ${n} 秒`,
      minutes: (n) => `每點 ${n} 分鐘`,
      hours: (n) => `每點 ${n} 小時`,
    },
    pointSpan: {
      seconds: (n) => `${n} 秒`,
      minutes: (n) => `${n} 分鐘`,
      hours: (n) => `${n} 小時`,
    },
    freshness: {
      updated: (resolution, when) => `${resolution} · ${when}更新`,
      reading: "讀取中…",
    },
    stale: {
      title: (time) => `無法更新：顯示的是 ${time} 的資料`,
      detail: "圖表與總量停在上次成功讀取的時間。",
    },
    loading: "載入數據統計",
    loadFailed: "無法載入數據統計",
    empty: {
      noConnections: "還沒有連線，沒有資料",
      noData: "這段時間沒有資料（連線未執行，或還沒有樣本）",
    },
    notFound: {
      title: "找不到這個對象",
      showAll: "改看全部連線",
      detail: (failure) => `${failure}：它可能已被刪除。`,
    },
    start: {
      title: "還沒有連線",
      add: "新增連線",
      detail: "建立連線並經代理埠傳送流量後，這裡會出現流量、連線數、DNS 與延遲的歷史。",
    },
    otherCharts: {
      label: "其他圖表",
      detail: "WireGuard、DNS 與 worker 資源屬於整條連線，代理埠沒有自己的這些數據。",
      viewOwner: (name) => `看所屬連線「${name}」`,
    },
    gaps: {
      missing: { detail: "連線未執行，或這段時間沒有記錄" },
      new_generation: {
        label: "重新啟動",
        detail: "新的 worker 從 0 開始計數（圖上的直線）；它的第一筆樣本還沒有速率",
      },
      long_interval: {
        label: "樣本間隔過長",
        detail: "兩筆樣本相隔超過 5 秒（例如主機睡眠），中間的速率無法計算",
      },
      counter_reset: { label: "計數器重置", detail: "計數器倒退或 worker 時鐘沒有前進，這段速率未知" },
      dropped: { label: "收集器丟棄", detail: "寫入資料庫太慢時丟棄的樣本" },
      quota: { label: "空間上限刪除", detail: "為了不超過指標空間上限而提前刪除的資料" },
      disk_low: {
        label: "磁碟空間不足",
        detail:
          "資料目錄的磁碟空間不足：為了繼續記錄最新的數據，最舊的資料被提前刪除（覆蓋）；連覆蓋都放不下時，這段時間的樣本才沒有儲存。控制資料與秘密不受影響",
      },
      unavailable: { label: "未回報", detail: "這台主機沒有提供 worker 的 CPU 或記憶體讀數" },
    },
    values: {
      noneCompleted: "沒有完成的連線",
      over: (limit) => `超過 ${limit}`,
      notFound: (n) => `（名稱不存在 ${n}）`,
      notFoundUnclassified: (known, earlier) => `（名稱不存在 ${known}，另 ${earlier} 次未分類）`,
      noDnsQueries: "沒有 DNS 查詢",
      perSecond: (rate) => `${rate} 次/秒`,
      openWindow: (start) => `${start} 起（尚未結束）`,
    },
    duration: {
      seconds: (s) => `${s} 秒`,
      minutes: (min, s) => (s ? `${min} 分 ${s} 秒` : `${min} 分`),
      hours: (h, min) => (min ? `${h} 小時 ${min} 分` : `${h} 小時`),
      days: (d, h) => (h ? `${d} 天 ${h} 小時` : `${d} 天`),
    },
    times: (n) => `${n} 次`,
    when: (relative, absolute) => `${relative}（${absolute}）`,
    noDataInRange: "範圍內沒有資料",
    availability: "可用率",
    ofWhich: "其中",
    listSeparator: "、",
    parts: {
      sshDownloads: "SSH 下載",
      sshProxy: "SSH 代理",
      appSandbox: "App 沙箱",
      appNames: (names) => names.join("、"),
    },
    deleted: {
      connection: (id) => `已刪除的連線（${id}）`,
      gateway: (id) => `已刪除的代理埠（${id}）`,
    },
    recording: {
      justNow: "剛才",
      diskFull: "磁碟已滿，已覆蓋最舊的紀錄",
      diskLow: "磁碟空間不足，已覆蓋最舊的紀錄",
      failingTitle: "數據無法寫入",
      failingDetail: (since, error) =>
        `從 ${since}起，新的樣本寫不進指標資料庫：${error}。樣本先放在佇列裡（滿了就捨棄最舊的，圖上是缺口），寫入恢復後自動繼續。`,
      failingAction: "查看指標寫入",
      overwriteDetail: (since, rows, label, lost, space) => {
        const notStored = lost > 0 ? `另有 ${lost} 筆樣本連覆蓋都放不下，沒有保存。` : "";
        const resume = space
          ? `資料目錄的可用空間 ${space.free}，回到 ${space.resume} 以上後恢復正常保存。`
          : "騰出磁碟空間後恢復正常保存。";
        return `新的數據照常記錄。指標資料庫不再變大，從 ${since}起提前刪除了 ${rows} 筆最舊的資料來騰出空間，圖上標為「${label}」。${notStored}${resume}`;
      },
      overwriteAction: "查看磁碟空間",
      failingLine: (error) => `數據無法寫入：${error}`,
      overwriteLine: (title) => `${title}：新的數據照常記錄。`,
    },
    summary: {
      label: "範圍摘要",
      header: (scope, range, resolution, covered, share, reporting) => (
        <>
          {scope}
          {` · ${range}（${resolution}）· 有資料的時間 `}
          {covered}
          {`（${share}）`}
          {reporting === null ? null : `，${reporting} 條連線回報`}
        </>
      ),
      peakUnknown: "峰值未知",
      peak: (rate, span) => `峰值 ${rate}（${span}平均）`,
      partSize: (label, size) => `${label} ${size}`,
      downloadHint:
        "應用程式經代理埠與轉發收到的資料，加上嚴格隔離的 App 沙箱裡 App 自己的連線收到的 TCP／UDP 資料（重送的封包也算）：只計連續樣本之間的計數器差，未回報的時間不計。其中 SSH 下載是 VPN Manager 的 SSH 下載工作，SSH 代理是經代理埠的 SSH 連線（vpnctl ssh-proxy、22 埠），兩者不重複",
      connectLatency: "連線延遲 p95",
      connects: (done, timeouts, failures, notFound) =>
        `完成 ${done} 次 · 逾時 ${timeouts} · 失敗 ${failures}${notFound}`,
      latencyHint:
        "代理連線（解析＋連線）的第 95 百分位，值為所在區間的上界；逾時不算延遲。失敗中的「名稱不存在」是 DNS 沒有這個名稱或沒有可用的位址，常見於被 DNS 封鎖的廣告／追蹤網域或只在區域網路有效的名稱，不是網路故障；「未分類」是開始區分之前（升級前）記錄的失敗",
      dnsFailureRate: "DNS 失敗率",
      dns: (queries, cacheHits, upstreamP95) => `查詢 ${queries} 次 · 快取 ${cacheHits} · 上游 p95 ${upstreamP95}`,
      gatewayDns: "代理埠沒有自己的 DNS：請看所屬連線",
      wireguardReceived: "WireGuard 接收",
      wireguardSent: (sent) => `傳送 ${sent}；加密封包，與流量不能相加`,
      gateUnknown: "部分時間沒有記錄閘門狀態",
      availabilityDetail: (recorded, serving, unrecorded) =>
        `有記錄的 ${recorded} 中接受連線 ${serving}${unrecorded === null ? "" : `；其餘 ${unrecorded} 沒有記錄，不計入`}`,
      availabilityHint:
        "閘門開放（接受新連線）的時間占有記錄時間的比例；沒有記錄的時間（未執行、主機睡眠或尚未開始記錄）不算可用也不算不可用",
      gapLegend: "缺口說明",
      spans: (n, duration) => `${n} 段 · ${duration}`,
      truncated: "缺口太多，只列出前 2000 段；圖上的空白仍然代表未知。",
    },
    breakdown: {
      columns: {
        rx: { hint: "應用程式收到的資料（連續樣本之間的計數器差）" },
        tx: { hint: "應用程式送出的資料" },
        peak: { label: "峰值下載", hint: "圖上下載的最高點（每點平均）" },
        p95: { label: "p95 連線延遲", hint: "代理連線的第 95 百分位（所在區間的上界）" },
        avail: { hint: "接受連線的時間占有記錄時間的比例；下方是有記錄的時間占範圍的比例" },
      },
      sortBy: (label) => `，依${label}排序`,
      notThroughProxy: "不經代理連線",
      inGateway: "算在代理埠",
      sameAsConnection: "同所屬連線",
      coverage: (share) => `資料 ${share}`,
      rows: {
        gateway: (port, withoutSsh) => `代理埠${port ? ` ${port}` : ""}${withoutSsh ? " · 不含 SSH" : ""}`,
        sandboxApps: (apps) => `嚴格隔離：${apps}`,
        sandbox: "嚴格隔離的 App",
        pull: "SSH 下載工作，經這條連線的代理埠",
        ssh: "SSH 連線（vpnctl ssh-proxy、22 埠），經這條連線的代理埠",
        connection: "連線",
      },
      deleted: "已刪除：只剩這個範圍的總量",
      showing: "頁面正在顯示這個對象",
      showingOwner: (name) => `頁面正在顯示所屬連線，${name}的流量就在它的圖表裡`,
      chartsOf: (name) => `只看「${name}」的圖表`,
      chartsOfOwner: (owner, part) => `只看「${owner}」的圖表（含 ${part}）`,
      titleParts: {
        connections: "各連線",
        gateways: "代理埠",
        sandboxes: "App 沙箱",
      },
      hint: (truncated) =>
        `同一範圍的總量；按欄位標題排序${truncated ? "。項目太多，只列出前 128 條連線與 128 個代理埠（上方總量仍包含全部）" : ""}`,
      tableLabel: (title) => `${title}在這個範圍的流量、延遲與可用率`,
      nameColumn: (ssh, sandboxes) => `連線／代理埠${ssh ? "／SSH" : ""}${sandboxes ? "／App 沙箱" : ""}`,
      empty: "這個範圍沒有連線或代理埠",
    },
  },
  ja: {
    title: "統計",
    description: "保存されたトラフィック、接続数、DNS、遅延、worker のリソース。",
    help: "どの数値にも範囲と対象期間を示しています。データのない時間は空白のままにし、理由は欠損の説明に記載し、再起動は縦線で示します。グラフにフォーカスすると ←／→ で 1 点ずつ確認できます（同じタブのグラフは同じカーソルを共有します）。どのグラフも表に切り替えられます。範囲、対象、並べ替え、タブはすべて URL に含まれます。",
    helpText: "データのない時間は空白にして理由を示します。グラフは ←／→ で 1 点ずつ確認でき、表にも切り替えられます。",
    views: {
      traffic: "トラフィック",
      latency: "遅延と DNS",
      resources: "リソース",
      breakdown: "接続ごと",
      retention: "保存",
    },
    toolStrip: "データの範囲",
    timeRange: "期間",
    ranges: {
      minutes: (n) => `${n} 分`,
      hours: (n) => `${n} 時間`,
      days: (n) => `${n} 日`,
      lastMinutes: (n) => `過去 ${n} 分間`,
      lastHours: (n) => `過去 ${n} 時間`,
      lastDays: (n) => `過去 ${n} 日間`,
    },
    scope: {
      label: "対象",
      current: (label) => `対象：${label}`,
      all: "すべての接続",
      connections: "接続",
      gateways: "ゲートウェイ",
      connectionId: (id) => `接続 ${id}`,
      gatewayId: (id) => `ゲートウェイ ${id}`,
      gateway: (name, port, owner) => `${name}（:${port}${owner ? `、${owner}` : ""}）`,
      missing: (label) => `${label}（見つかりません）`,
    },
    resolution: {
      seconds: (n) => `1 点あたり ${n} 秒`,
      minutes: (n) => `1 点あたり ${n} 分`,
      hours: (n) => `1 点あたり ${n} 時間`,
    },
    pointSpan: {
      seconds: (n) => `${n} 秒`,
      minutes: (n) => `${n} 分`,
      hours: (n) => `${n} 時間`,
    },
    freshness: {
      updated: (resolution, when) => `${resolution} · 更新：${when}`,
      reading: "読み込み中…",
    },
    stale: {
      title: (time) => `更新できません：${time} 時点のデータを表示しています`,
      detail: "グラフと合計は、最後に読み込みに成功した時点のままです。",
    },
    loading: "統計を読み込み中",
    loadFailed: "統計を読み込めません",
    empty: {
      noConnections: "まだ接続がないため、データはありません",
      noData: "この期間のデータはありません（接続が実行されていないか、まだサンプルがありません）",
    },
    notFound: {
      title: "この対象が見つかりません",
      showAll: "すべての接続を表示",
      detail: (failure) => `${failure}：削除された可能性があります。`,
    },
    start: {
      title: "まだ接続がありません",
      add: "接続を追加",
      detail:
        "接続を作成してゲートウェイ経由でトラフィックを送ると、トラフィック、接続数、DNS、遅延の履歴がここに表示されます。",
    },
    otherCharts: {
      label: "その他のグラフ",
      detail: "WireGuard、DNS、worker のリソースは接続全体のもので、ゲートウェイにはこれらの独自のデータがありません。",
      viewOwner: (name) => `所属する接続「${name}」を表示`,
    },
    gaps: {
      missing: { detail: "接続が実行されていなかったか、この間の記録がありません" },
      new_generation: {
        label: "再起動",
        detail: "新しい worker が 0 から数え直します（グラフの縦線）。その最初のサンプルにはまだ速度がありません",
      },
      long_interval: {
        label: "サンプル間隔が長すぎる",
        detail: "2 つのサンプルの間隔が 5 秒を超えたため（ホストのスリープなど）、その間の速度を計算できません",
      },
      counter_reset: {
        label: "カウンターのリセット",
        detail: "カウンターが逆戻りしたか、worker の時計が進みませんでした。この区間の速度は不明です",
      },
      dropped: { label: "コレクターが破棄", detail: "データベースへの書き込みが遅すぎたときに破棄されたサンプル" },
      quota: { label: "容量上限による削除", detail: "メトリクスの容量上限を超えないように早めに削除されたデータ" },
      disk_low: {
        label: "ディスク容量不足",
        detail:
          "データディレクトリのディスク容量が不足しています。最新のデータを記録し続けるため、最も古いデータを早めに削除（上書き）しました。上書きしても収まらなかったときだけ、この間のサンプルが保存されていません。制御データとシークレットには影響しません",
      },
      unavailable: { label: "未報告", detail: "このホストは worker の CPU またはメモリの値を報告しません" },
    },
    values: {
      noneCompleted: "完了した接続なし",
      over: (limit) => `${limit} を超過`,
      notFound: (n) => `（存在しない名前 ${n}）`,
      notFoundUnclassified: (known, earlier) => `（存在しない名前 ${known}、ほかに未分類 ${earlier} 回）`,
      noDnsQueries: "DNS クエリなし",
      perSecond: (rate) => `${rate} 回/秒`,
      openWindow: (start) => `${start} から（未終了）`,
    },
    duration: {
      seconds: (s) => `${s} 秒`,
      minutes: (min, s) => (s ? `${min} 分 ${s} 秒` : `${min} 分`),
      hours: (h, min) => (min ? `${h} 時間 ${min} 分` : `${h} 時間`),
      days: (d, h) => (h ? `${d} 日 ${h} 時間` : `${d} 日`),
    },
    times: (n) => `${n} 回`,
    when: (relative, absolute) => `${relative}（${absolute}）`,
    noDataInRange: "この範囲にデータなし",
    availability: "稼働率",
    ofWhich: "うち",
    listSeparator: "、",
    parts: {
      sshDownloads: "SSH ダウンロード",
      sshProxy: "SSH プロキシ",
      appSandbox: "アプリのサンドボックス",
      appNames: (names) => names.join("、"),
    },
    deleted: {
      connection: (id) => `削除された接続（${id}）`,
      gateway: (id) => `削除されたゲートウェイ（${id}）`,
    },
    recording: {
      justNow: "たった今",
      diskFull: "ディスクがいっぱいのため、最も古い記録を上書きしました",
      diskLow: "ディスク容量が不足しているため、最も古い記録を上書きしました",
      failingTitle: "統計データを書き込めません",
      failingDetail: (since, error) =>
        `${since}から、新しいサンプルをメトリクスデータベースに書き込めません：${error}。サンプルはいったんキューに入ります（いっぱいになると最も古いものから破棄され、グラフでは欠損になります）。書き込みが回復すると自動的に再開します。`,
      failingAction: "メトリクスの書き込みを確認",
      overwriteDetail: (since, rows, label, lost, space) => {
        const notStored = lost > 0 ? `ほかに ${lost} 件のサンプルは上書きしても収まらず、保存されませんでした。` : "";
        const resume = space
          ? `データディレクトリの空き容量は ${space.free} です。${space.resume} 以上に戻ると通常の保存を再開します。`
          : "ディスクの空き容量を確保すると通常の保存を再開します。";
        return `新しいデータは通常どおり記録されています。メトリクスデータベースはこれ以上大きくならず、${since}から最も古いデータ ${rows} 件を早めに削除して空きを確保しました。グラフでは「${label}」と表示されます。${notStored}${resume}`;
      },
      overwriteAction: "ディスク容量を確認",
      failingLine: (error) => `統計データを書き込めません：${error}`,
      overwriteLine: (title) => `${title}：新しいデータは通常どおり記録されています。`,
    },
    summary: {
      label: "範囲の概要",
      header: (scope, range, resolution, covered, share, reporting) => (
        <>
          {scope}
          {` · ${range}（${resolution}）· データのある時間 `}
          {covered}
          {`（${share}）`}
          {reporting === null ? null : `、${reporting} 件の接続が報告`}
        </>
      ),
      peakUnknown: "ピーク不明",
      peak: (rate, span) => `ピーク ${rate}（${span}平均）`,
      partSize: (label, size) => `${label} ${size}`,
      downloadHint:
        "アプリケーションがゲートウェイとポート転送経由で受信したデータに、厳格な分離のアプリのサンドボックス内でアプリ自身の接続が受信した TCP／UDP データ（再送パケットを含む）を加えたもの。連続するサンプル間のカウンターの差だけを数え、報告のない時間は数えません。うち SSH ダウンロードは VPN Manager の SSH ダウンロードジョブ、SSH プロキシはゲートウェイ経由の SSH 接続（vpnctl ssh-proxy、22 番ポート）で、両者は重複しません",
      connectLatency: "接続遅延 p95",
      connects: (done, timeouts, failures, notFound) =>
        `完了 ${done} 回 · タイムアウト ${timeouts} · 失敗 ${failures}${notFound}`,
      latencyHint:
        "プロキシ接続（名前解決＋接続）の 95 パーセンタイルで、値はその区間の上限です。タイムアウトは遅延に数えません。失敗のうち「存在しない名前」は、DNS にその名前がないか使えるアドレスがないもので、DNS でブロックされた広告／トラッキングのドメインや、ローカルネットワークでだけ有効な名前によく見られ、ネットワークの障害ではありません。「未分類」は、区別を始める前（アップグレード前）に記録された失敗です",
      dnsFailureRate: "DNS 失敗率",
      dns: (queries, cacheHits, upstreamP95) =>
        `クエリ ${queries} 回 · キャッシュ ${cacheHits} · 上流 p95 ${upstreamP95}`,
      gatewayDns: "ゲートウェイには独自の DNS がありません。所属する接続を見てください",
      wireguardReceived: "WireGuard 受信",
      wireguardSent: (sent) => `送信 ${sent}。暗号化されたパケットで、トラフィックとは合算できません`,
      gateUnknown: "一部の時間はゲートの状態が記録されていません",
      availabilityDetail: (recorded, serving, unrecorded) =>
        `記録された ${recorded} のうち接続を受け付けていたのは ${serving}${unrecorded === null ? "" : `。残りの ${unrecorded} は記録がなく、含めていません`}`,
      availabilityHint:
        "記録された時間のうち、ゲートが開いていた（新しい接続を受け付けていた）時間の割合。記録のない時間（実行されていない、ホストがスリープ中、記録開始前）は稼働とも非稼働とも数えません",
      gapLegend: "欠損の説明",
      spans: (n, duration) => `${n} 区間 · ${duration}`,
      truncated: "欠損が多すぎるため、最初の 2000 区間だけを表示しています。グラフの空白は引き続き不明を意味します。",
    },
    breakdown: {
      columns: {
        rx: { hint: "アプリケーションが受信したデータ（連続するサンプル間のカウンターの差）" },
        tx: { hint: "アプリケーションが送信したデータ" },
        peak: { label: "ダウンロードのピーク", hint: "グラフ上のダウンロードの最高点（各点は平均）" },
        p95: { label: "p95 接続遅延", hint: "プロキシ接続の 95 パーセンタイル（その区間の上限）" },
        avail: { hint: "記録された時間のうち接続を受け付けていた時間の割合。下は範囲のうち記録のある時間の割合" },
      },
      sortBy: (label) => `、${label}で並べ替え`,
      notThroughProxy: "プロキシを経由しない",
      inGateway: "ゲートウェイに計上",
      sameAsConnection: "所属する接続と同じ",
      coverage: (share) => `データ ${share}`,
      rows: {
        gateway: (port, withoutSsh) => `ゲートウェイ${port ? ` ${port}` : ""}${withoutSsh ? " · SSH を除く" : ""}`,
        sandboxApps: (apps) => `厳格な分離：${apps}`,
        sandbox: "厳格な分離のアプリ",
        pull: "SSH ダウンロードジョブ、この接続のゲートウェイ経由",
        ssh: "SSH 接続（vpnctl ssh-proxy、22 番ポート）、この接続のゲートウェイ経由",
        connection: "接続",
      },
      deleted: "削除済み：この範囲の合計だけが残っています",
      showing: "ページはこの対象を表示しています",
      showingOwner: (name) => `ページは所属する接続を表示しています。${name}のトラフィックはそのグラフに含まれます`,
      chartsOf: (name) => `「${name}」のグラフだけを表示`,
      chartsOfOwner: (owner, part) => `「${owner}」のグラフだけを表示（${part}を含む）`,
      titleParts: {
        connections: "接続",
        gateways: "ゲートウェイ",
        sandboxes: "アプリのサンドボックス",
      },
      hint: (truncated) =>
        `同じ範囲の合計。列見出しで並べ替え${truncated ? "。項目が多すぎるため、最初の 128 件の接続と 128 件のゲートウェイだけを表示しています（上の合計にはすべて含まれます）" : ""}`,
      tableLabel: (title) => `${title}のこの範囲のトラフィック、遅延、稼働率`,
      nameColumn: (ssh, sandboxes) =>
        `接続／ゲートウェイ${ssh ? "／SSH" : ""}${sandboxes ? "／アプリのサンドボックス" : ""}`,
      empty: "この範囲には接続もゲートウェイもありません",
    },
  },
});
