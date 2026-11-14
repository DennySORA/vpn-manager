// Text of the charts: the card around a chart with its legend and its table, the readout of a series chart and the
// live rate chart. 下載, 上傳 and 未知 are the shared words (components/ui/messages.ts, `common`).

import { defineMessages } from "@/i18n";

/** One series at the cursor: its name and its value as text. */
interface SeriesValue {
  label: string;
  value: string;
}

export const m = defineMessages({
  en: {
    legend: "Legend",
    time: "Time",
    table: "Table",
    /** The table toggle of one chart, named after the chart. */
    tableOf: (title: string) => `${title}: table`,
    tableCaption: (caption: string) => `${caption}: the values of each time interval, newest first`,
    rowsShown: (shown: number, total: number) =>
      shown === 1
        ? `Only the newest row is listed (${total} in all).`
        : `Only the newest ${shown} rows are listed (${total} in all).`,
    /** What a series chart announces at the cursor: the window, then each series with its value. */
    readout: (window: string, values: readonly SeriesValue[]) =>
      `${window}: ${values.map((v) => `${v.label} ${v.value}`).join(", ")}`,
    rate: {
      empty: "No live data yet",
      /** The chart in one sentence, for assistive technology. */
      summary: (minutes: number, peak: string, download: string, upload: string) =>
        `Last ${minutes} ${minutes === 1 ? "minute" : "minutes"}: peak download ${peak}; now download ${download}, upload ${upload}`,
      /** The left end of the time axis. */
      minutesAgo: (minutes: number) => `${minutes} min ago`,
      now: "Now",
      /** What the chart announces at the cursor. */
      at: (time: string, download: string, upload: string) => `${time}: download ${download}, upload ${upload}`,
      recent: "Show recent values",
      recentCaption: "Recent live rates, newest first",
    },
  },
  "zh-TW": {
    legend: "圖例",
    time: "時間",
    table: "表格",
    tableOf: (title) => `${title}：表格`,
    tableCaption: (caption) => `${caption}：每個時間區間的數值，最新在前`,
    rowsShown: (shown, total) => `只列出最新的 ${shown} 列（共 ${total} 列）。`,
    readout: (window, values) => `${window}：${values.map((v) => `${v.label} ${v.value}`).join("，")}`,
    rate: {
      empty: "尚無即時數據",
      summary: (minutes, peak, download, upload) =>
        `過去 ${minutes} 分鐘：下載峰值 ${peak}，目前下載 ${download}、上傳 ${upload}`,
      minutesAgo: (minutes) => `${minutes} 分鐘前`,
      now: "現在",
      at: (time, download, upload) => `${time}：下載 ${download}，上傳 ${upload}`,
      recent: "查看最近數值",
      recentCaption: "最近的即時速率，最新在前",
    },
  },
  ja: {
    legend: "凡例",
    time: "時刻",
    table: "表",
    tableOf: (title) => `${title}：表`,
    tableCaption: (caption) => `${caption}：各時間区間の値、新しい順`,
    rowsShown: (shown, total) => `最新の ${shown} 行のみ表示しています（全 ${total} 行）。`,
    readout: (window, values) => `${window}：${values.map((v) => `${v.label} ${v.value}`).join("、")}`,
    rate: {
      empty: "リアルタイムのデータはまだありません",
      summary: (minutes, peak, download, upload) =>
        `過去 ${minutes} 分間：ダウンロードのピーク ${peak}、現在のダウンロード ${download}、アップロード ${upload}`,
      minutesAgo: (minutes) => `${minutes} 分前`,
      now: "現在",
      at: (time, download, upload) => `${time}：ダウンロード ${download}、アップロード ${upload}`,
      recent: "最近の値を表示",
      recentCaption: "最近のリアルタイム速度、新しい順",
    },
  },
});
