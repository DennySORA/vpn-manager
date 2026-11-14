// Text of the top bar's traffic strip: its accessible sentence, and the popover with one row per running connection.
// 連線 is a connection (an Instance); 連線數 counts the TCP connections and UDP flows open in the tunnels.

import { defineMessages, intlLocale } from "@/i18n";

const integer = new Intl.NumberFormat(intlLocale);

function connectionsEn(count: number): string {
  return `${count} ${count === 1 ? "connection" : "connections"}`;
}

/** The running connections without a fresh sample, after the total they are left out of. */
function notCountedEn(missing: number): string {
  return missing > 0 ? `; ${missing} without live data ${missing === 1 ? "is" : "are"} not counted` : "";
}

function notCountedZh(missing: number): string {
  return missing > 0 ? `；${missing} 條沒有即時數據，未計入` : "";
}

function notCountedJa(missing: number): string {
  return missing > 0 ? `、リアルタイムのデータがない ${missing} 件は含みません` : "";
}

export const m = defineMessages({
  en: {
    title: "Live traffic",
    /** The strip's accessible name: every figure in one sentence. */
    sentence: {
      none: "Live traffic: no running connections",
      noData: (running: number) =>
        `Live traffic: ${running} running ${running === 1 ? "connection has" : "connections have"} no live data yet`,
      total: (download: string, upload: string, flows: string, fresh: number, missing: number) =>
        `Live traffic: download ${download}, upload ${upload}, TCP/UDP flows ${flows} (${connectionsEn(fresh)}${notCountedEn(missing)})`,
    },
    panel: {
      none: "No running connections.",
      total: (fresh: number, download: string, upload: string, flows: string, missing: number) =>
        `${connectionsEn(fresh)} in total ↓ ${download} ↑ ${upload} · TCP/UDP flows ${flows}; updated every second${notCountedEn(missing)}`,
      waiting: "No live data yet: it updates every second once a connection is ready.",
      scope:
        "Data that applications send and receive through Gateways, port forwards and the strictly isolated app sandbox, in bit/s; SSH downloads and the SSH proxy are listed separately.",
      connections: "Running connections",
      viewAll: "View in Connections",
    },
    row: {
      noData:
        "No live data: no sample from this connection arrived in the last 3.5 seconds, so it is not counted in the total.",
      /** A part of a connection's rates, before its figures (“of which SSH downloads ↓ … ↑ …”). */
      part: (label: string) => `of which ${label}`,
      sshDownloads: "SSH downloads",
      sshProxy: "SSH proxy",
      appSandbox: "App sandbox",
      sshSessions: (sessions: number) =>
        `${integer.format(sessions)} SSH ${sessions === 1 ? "connection" : "connections"}`,
    },
  },
  "zh-TW": {
    title: "即時流量",
    sentence: {
      none: "即時流量：沒有執行中的連線",
      noData: (running) => `即時流量：${running} 條執行中的連線還沒有即時數據`,
      total: (download, upload, flows, fresh, missing) =>
        `即時流量：下載 ${download}、上傳 ${upload}、連線數 ${flows}（${fresh} 條連線${notCountedZh(missing)}）`,
    },
    panel: {
      none: "沒有執行中的連線。",
      total: (fresh, download, upload, flows, missing) =>
        `${fresh} 條連線合計 ↓ ${download} ↑ ${upload} · 連線數 ${flows}；每秒更新${notCountedZh(missing)}`,
      waiting: "還沒有即時數據：連線就緒後每秒更新。",
      scope: "應用程式經代理埠、轉發與嚴格隔離的 App 沙箱收發的資料，bit/s；SSH 下載與 SSH 代理另外列出。",
      connections: "執行中的連線",
      viewAll: "在連線頁查看",
    },
    row: {
      noData: "沒有即時數據：最近 3.5 秒沒有收到這條連線的樣本，不算進合計。",
      part: (label) => `其中 ${label}`,
      sshDownloads: "SSH 下載",
      sshProxy: "SSH 代理",
      appSandbox: "App 沙箱",
      sshSessions: (sessions) => `${integer.format(sessions)} 條 SSH 連線`,
    },
  },
  ja: {
    title: "リアルタイムトラフィック",
    sentence: {
      none: "リアルタイムトラフィック：実行中の接続はありません",
      noData: (running) =>
        `リアルタイムトラフィック：実行中の ${running} 件の接続にはまだリアルタイムのデータがありません`,
      total: (download, upload, flows, fresh, missing) =>
        `リアルタイムトラフィック：ダウンロード ${download}、アップロード ${upload}、TCP/UDP フロー ${flows}（接続 ${fresh} 件${notCountedJa(missing)}）`,
    },
    panel: {
      none: "実行中の接続はありません。",
      total: (fresh, download, upload, flows, missing) =>
        `${fresh} 件の接続の合計 ↓ ${download} ↑ ${upload} · TCP/UDP フロー ${flows}、毎秒更新${notCountedJa(missing)}`,
      waiting: "リアルタイムのデータはまだありません。接続が準備完了になると毎秒更新されます。",
      scope:
        "アプリケーションがゲートウェイ、ポート転送、厳格に分離されたアプリのサンドボックスを通じて送受信するデータ（bit/s）。SSH ダウンロードと SSH プロキシは別に表示します。",
      connections: "実行中の接続",
      viewAll: "接続ページで表示",
    },
    row: {
      noData: "リアルタイムのデータなし：直近 3.5 秒間にこの接続のサンプルを受信していないため、合計には含めません。",
      part: (label) => `うち ${label}`,
      sshDownloads: "SSH ダウンロード",
      sshProxy: "SSH プロキシ",
      appSandbox: "アプリのサンドボックス",
      sshSessions: (sessions) => `${integer.format(sessions)} 件の SSH 接続`,
    },
  },
});
