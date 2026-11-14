// Text of the inspector of one SSH download job: why it waits or stopped, the files in flight, the SSH traffic, the
// queue, the download history, the log and the job's settings. A sub-area of the SSH downloads page: the words it
// shares with the list and the dialog (states, steps, filters, record settings, shared labels) are in ../messages.ts.
// Relative times (`when`, `ago`) come from lib/format.ts in this language.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** A phrase that starts a sentence, inside one: "The newest 500 …" → "the newest 500 …". */
function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}

export const m = defineMessages({
  en: {
    actionsOf: (name: string) => `Actions for ${name}`,
    viewsOf: (name: string) => `Views of ${name}`,
    idLabel: "download job ID",
    tabs: { progress: "Progress", history: "History", log: "Log", settings: "Settings" },
    /** Why the job waits or stopped, and the fail-closed rule. */
    problem: {
      hostKeyChanged: "The server's host key changed",
      hostKeyStopped:
        "The job has stopped without sending any login details. Make sure the server was reinstalled, then trust the new key.",
      recordedKey: (fingerprint: string) => `Recorded: ${fingerprint}`,
      offeredKey: (fingerprint: string) => `Offered now: ${fingerprint}`,
      /** `when`: the time until the next check, or null once it is due. */
      recheck: (when: string | null) =>
        when === null ? "It checks again automatically in a moment." : `It checks again automatically ${when}.`,
      /** `planned`: a next attempt is planned; `when`: the time until it, or null once it is due. */
      waiting: (planned: boolean, when: string | null) =>
        `Meanwhile it does not connect, and never falls back to the ordinary network; it continues by itself once the connection is ready${
          planned ? ` (${when ? `next attempt ${when}` : "trying again shortly"})` : ""
        }.`,
      nextTry: (when: string | null) => `${when ? `Next attempt ${when}` : "Trying again shortly"}.`,
      pausedUnfinished: (count: number) =>
        count === 1
          ? "The unfinished file continues downloading where it stopped once the job resumes."
          : `The ${count} unfinished files continue downloading where they stopped once the job resumes.`,
      pausedIdle: "It connects and scans the source folder only once the job resumes.",
      unknown: "State unknown",
      unknownBody: "The core service has not reported this job; the VPN connections are not affected.",
      /** Through which Gateway (and its connection; null when unknown) the job reaches `host`. */
      onlyVia: (gateway: string | null, connection: string | null, host: string) =>
        `Connects to ${host} only through the tunnel of ${
          gateway === null
            ? "the chosen Gateway"
            : `the Gateway “${gateway}”${connection === null ? "" : ` (connection “${connection}”)`}`
        }; while the VPN is not ready or the Gateway refuses, it waits and never connects directly.`,
    },
    /** The last scan and the next one (`planned`; `when` is null once it is due). */
    lastScan: (ago: string, planned: boolean, when: string | null) =>
      `Last scan ${ago}${planned ? ` · ${when ? `next ${when}` : "scanning again shortly"}` : ""}`,
    neverScanned: "The source folder has not been scanned yet",
    active: {
      title: "In progress",
      of: (name: string) => `Files in progress for ${name}`,
      scanning: "Scanning the source folder…",
      none: "No file is being downloaded.",
      remaining: (eta: string) => `${eta} left`,
      connections: (count: number) => `${count} ${count === 1 ? "connection" : "connections"}`,
      resumedFrom: (bytes: string) => `Resumed from ${bytes}`,
      attempt: (attempt: number) => `Attempt ${attempt} (the earlier ones made no progress)`,
    },
    traffic: {
      title: "SSH traffic",
      rateHint: "Bytes the SSH connections send and receive through the Gateway (encryption and packets included)",
      total: "Total",
      sinceStart: "Since the core service last started",
      runTime: "Running time",
      startedAt: (time: string) => `Started ${time}`,
      notTimed: "Not counted while paused or stopped",
      path: "Path",
      pathHint: "This traffic also counts toward this Gateway and its connection",
      /** The Gateway the traffic goes through (a link), and its connection. */
      via: (link: ReactNode, connection: string | null): ReactNode => (
        <>
          Through {link}
          {connection === null ? null : ` (${connection})`}
        </>
      ),
    },
    queue: {
      title: "Queue",
      waiting: "Waiting to download",
      truncated: "The scan stopped at 10,000 items; the next scan lists the rest",
      unfinished: "Unfinished",
      unfinishedHint: "Files taken earlier and not finished yet continue downloading first",
      connections: "Connections",
      connectionsHint: "SSH connections open through the Gateway",
      connectionsOf: (open: number, max: number) => `${open} / ${max}`,
      lastScan: "Last scan",
      skipped: (count: number) =>
        `Skipped ${count} ${count === 1 ? "item" : "items"} (folders, links or filtered names)`,
      /** A moment, relative and absolute. */
      at: (relative: string, absolute: string) => `${relative} (${absolute})`,
      sinceStart: "Since start",
      tally: (completed: number, failed: number, bytes: string) =>
        `${completed} completed · ${failed} failed · ${bytes}`,
      retrying: "Files waiting to retry",
    },
    history: {
      title: "Download history",
      reading: "Reading the download history",
      failed: "Cannot read the download history",
      of: (name: string) => `Download history of ${name}`,
      loading: "Loading",
      older: "Load earlier records",
      /** What is kept (the record settings in words), at the end of the history. */
      kept: (kept: string, names: string) => `Kept: ${lowerFirst(kept)}; ${lowerFirst(names)}.`,
      none: "No file has finished or failed yet.",
    },
    /** A finished or waiting transfer. */
    transfer: {
      namesOff: "This job does not record file names",
      /** After the transfer number of a file whose name is not kept. */
      nameOff: " · name not recorded",
      sizeUnknown: "Size unknown",
      noProgress: (count: number) => `${count} ${count === 1 ? "attempt" : "attempts"} without progress`,
      remote: (path: string) => `Remote: ${path}`,
    },
    log: {
      title: "Log",
      failed: "Cannot read the log",
      of: (name: string) => `Log of ${name} (newest first)`,
      none: "Nothing logged yet.",
    },
    settings: {
      connection: "Connection",
      gatewayOwner: (name: string, state: string) => `Connection “${name}”: ${state}`,
      gatewayAddress: (name: string, port: number) => `${name} (127.0.0.1:${port})`,
      loginHint: "Passwords and key passphrases are kept only in the key vault and are never shown",
      privateKey: (file: string) => `Private key ${file}`,
      passphraseStored: "Key passphrase stored",
      passwordStored: "Password stored",
      hostKey: "Host key",
      hostKeySeen: (algorithm: string, time: string) => `${algorithm} · recorded at the first connection, ${time}`,
      hostKeyFirst: "Recorded at the first connection; only that key is accepted afterwards",
      neverConnected: "Not connected yet",
      folders: "Folders",
      source: "Source",
      sourceHint: "Remote",
      work: "Working",
      workHint: "Files being downloaded are kept here under UUID names",
      failed: "Failed",
      local: "Local",
      localHint: "Partial files are in its .vpn-manager-partial",
      title: "Settings",
      concurrent: "Concurrent connections",
      attemptsHint: "Attempts in a row without progress",
      attempts: (count: number) => String(count),
      backoff: (secs: number) => `From ${secs} s`,
      scanInterval: (secs: number) => `${secs} s`,
      dotFiles: "Files starting with .",
      skipped: "Skipped",
      downloaded: "Downloaded too",
      created: "Created",
      fileNames: "File names",
      fileNamesOn: "The log and the transfer history show file names and paths",
      fileNamesOff:
        "Unfinished files keep their names until they finish, so they can resume; files being downloaded still show their names live",
      kept: "Kept",
      keptHint: "Cleared and expired records do not stay in the database",
    },
  },
  "zh-TW": {
    actionsOf: (name) => `${name} 的操作`,
    viewsOf: (name) => `${name} 的檢視`,
    idLabel: "下載工作 ID",
    tabs: { progress: "進度", history: "紀錄", log: "日誌", settings: "設定" },
    problem: {
      hostKeyChanged: "伺服器的主機金鑰改變了",
      hostKeyStopped: "工作已停止，沒有送出任何登入資料。確認伺服器是重新安裝過的，再信任新的金鑰。",
      recordedKey: (fingerprint) => `記錄的 ${fingerprint}`,
      offeredKey: (fingerprint) => `現在提供 ${fingerprint}`,
      recheck: (when) => `${when ?? "即將"}自動再檢查一次。`,
      waiting: (planned, when) =>
        `這段期間不會連線，也不會改走一般網路；連線就緒後自動繼續${
          planned ? `（${when ? `下次嘗試 ${when}` : "即將再試"}）` : ""
        }。`,
      nextTry: (when) => `${when ? `下次嘗試 ${when}` : "即將再試"}。`,
      pausedUnfinished: (count) => `未完成的 ${count} 個檔案會在繼續後從中斷處接著下載。`,
      pausedIdle: "繼續後才會連線、掃描來源資料夾。",
      unknown: "狀態未知",
      unknownBody: "核心服務沒有回報這個工作；VPN 連線不受影響。",
      onlyVia: (gateway, connection, host) =>
        `只經${
          gateway === null
            ? "選定的代理埠"
            : `代理埠「${gateway}」${connection === null ? "" : `（連線「${connection}」）`}`
        }的 tunnel 連到 ${host}；VPN 未就緒或代理埠拒絕時等待，不會直接連線。`,
    },
    lastScan: (ago, planned, when) => `上次掃描 ${ago}${planned ? ` · ${when ? `下次 ${when}` : "即將再掃描"}` : ""}`,
    neverScanned: "還沒有掃描過來源資料夾",
    active: {
      title: "進行中",
      of: (name) => `${name} 進行中的檔案`,
      scanning: "正在掃描來源資料夾…",
      none: "沒有正在下載的檔案。",
      remaining: (eta) => `剩 ${eta}`,
      connections: (count) => `${count} 條連線`,
      resumedFrom: (bytes) => `從 ${bytes} 接續下載`,
      attempt: (attempt) => `第 ${attempt} 次嘗試（前幾次沒有進展）`,
    },
    traffic: {
      title: "SSH 流量",
      rateHint: "SSH 連線經代理埠收送的位元組（含加密與封包）",
      total: "累計",
      sinceStart: "核心服務這次啟動以來",
      runTime: "執行時間",
      startedAt: (time) => `${time} 開始`,
      notTimed: "暫停或停止時不計時",
      path: "路徑",
      pathHint: "這些流量也計入這個代理埠和它的連線的流量",
      via: (link, connection) => (
        <>
          經 {link}
          {connection === null ? null : `（${connection}）`}
        </>
      ),
    },
    queue: {
      title: "佇列",
      waiting: "等待下載",
      truncated: "掃描在 10,000 個項目停止；其餘下次掃描再列出",
      unfinished: "未完成",
      unfinishedHint: "先前取走、尚未完成的檔案會先接著下載",
      connections: "連線",
      connectionsHint: "經代理埠開著的 SSH 連線",
      connectionsOf: (open, max) => `${open}／${max}`,
      lastScan: "上次掃描",
      skipped: (count) => `略過 ${count} 個項目（資料夾、連結或被篩選的名稱）`,
      at: (relative, absolute) => `${relative}（${absolute}）`,
      sinceStart: "這次啟動以來",
      tally: (completed, failed, bytes) => `完成 ${completed} · 失敗 ${failed} · ${bytes}`,
      retrying: "等待重試的檔案",
    },
    history: {
      title: "下載紀錄",
      reading: "讀取下載紀錄",
      failed: "無法讀取下載紀錄",
      of: (name) => `${name} 的下載紀錄`,
      loading: "載入中",
      older: "載入更早的紀錄",
      kept: (kept, names) => `保留：${kept}；${names}。`,
      none: "還沒有下載完成或失敗的檔案。",
    },
    transfer: {
      namesOff: "這個工作不記錄檔名",
      nameOff: " · 未記錄檔名",
      sizeUnknown: "大小未知",
      noProgress: (count) => `${count} 次沒有進展`,
      remote: (path) => `遠端：${path}`,
    },
    log: {
      title: "日誌",
      failed: "無法讀取日誌",
      of: (name) => `${name} 的日誌（最新在上）`,
      none: "還沒有紀錄。",
    },
    settings: {
      connection: "連線",
      gatewayOwner: (name, state) => `連線「${name}」${state}`,
      gatewayAddress: (name, port) => `${name}（127.0.0.1:${port}）`,
      loginHint: "密碼與金鑰密碼只存在金鑰保管庫，不會顯示",
      privateKey: (file) => `私鑰 ${file}`,
      passphraseStored: "金鑰密碼已儲存",
      passwordStored: "密碼已儲存",
      hostKey: "主機金鑰",
      hostKeySeen: (algorithm, time) => `${algorithm} · ${time} 第一次連線時記錄`,
      hostKeyFirst: "第一次連線時記錄，之後只接受這把",
      neverConnected: "尚未連線過",
      folders: "資料夾",
      source: "來源",
      sourceHint: "遠端",
      work: "處理中",
      workHint: "下載中的檔案以 UUID 名稱放這裡",
      failed: "失敗",
      local: "本機",
      localHint: "部分檔案在其中的 .vpn-manager-partial",
      title: "設定",
      concurrent: "同時連線",
      attemptsHint: "連續沒有進展的次數",
      attempts: (count) => `${count} 次`,
      backoff: (secs) => `${secs} 秒起`,
      scanInterval: (secs) => `${secs} 秒`,
      dotFiles: ". 開頭的檔案",
      skipped: "略過",
      downloaded: "一併下載",
      created: "建立",
      fileNames: "檔名",
      fileNamesOn: "日誌與傳輸紀錄寫出檔名與路徑",
      fileNamesOff: "未完成的檔案在完成前保留檔名，以便接著下載；下載中的檔案仍即時顯示名稱",
      kept: "保留",
      keptHint: "清除的與過期的紀錄不留在資料庫裡",
    },
  },
  ja: {
    actionsOf: (name) => `${name} の操作`,
    viewsOf: (name) => `${name} の表示`,
    idLabel: "ダウンロードジョブ ID",
    tabs: { progress: "進捗", history: "履歴", log: "ログ", settings: "設定" },
    problem: {
      hostKeyChanged: "サーバーのホスト鍵が変わりました",
      hostKeyStopped:
        "ジョブは停止しました。ログイン情報は送信していません。サーバーが再インストールされたことを確認してから、新しい鍵を信頼してください。",
      recordedKey: (fingerprint) => `記録済み：${fingerprint}`,
      offeredKey: (fingerprint) => `今回の提示：${fingerprint}`,
      recheck: (when) =>
        when === null ? "まもなく自動的にもう一度確認します。" : `${when}に自動的にもう一度確認します。`,
      waiting: (planned, when) =>
        `この間は接続せず、通常のネットワークにも切り替わりません。接続の準備ができると自動的に再開します${
          planned ? `（${when ? `次回の試行：${when}` : "まもなく再試行"}）` : ""
        }。`,
      nextTry: (when) => (when ? `次回の試行：${when}。` : "まもなく再試行します。"),
      pausedUnfinished: (count) =>
        `未完了の ${count} 件のファイルは、再開後に中断したところから続きをダウンロードします。`,
      pausedIdle: "再開すると、接続して取得元フォルダーをスキャンします。",
      unknown: "状態不明",
      unknownBody: "コアサービスがこのジョブを報告していません。VPN 接続には影響しません。",
      onlyVia: (gateway, connection, host) =>
        `${
          gateway === null
            ? "選んだゲートウェイ"
            : `ゲートウェイ「${gateway}」${connection === null ? "" : `（接続「${connection}」）`}`
        }のトンネルだけを通って ${host} に接続します。VPN の準備ができていないときやゲートウェイが拒否したときは待機し、直接接続はしません。`,
    },
    lastScan: (ago, planned, when) =>
      `前回のスキャン：${ago}${planned ? ` · ${when ? `次回：${when}` : "まもなく再スキャン"}` : ""}`,
    neverScanned: "取得元フォルダーはまだスキャンしていません",
    active: {
      title: "進行中",
      of: (name) => `${name} の進行中のファイル`,
      scanning: "取得元フォルダーをスキャンしています…",
      none: "ダウンロード中のファイルはありません。",
      remaining: (eta) => `残り ${eta}`,
      connections: (count) => `${count} 本の接続`,
      resumedFrom: (bytes) => `${bytes} から再開`,
      attempt: (attempt) => `${attempt} 回目の試行（前回までは進展なし）`,
    },
    traffic: {
      title: "SSH トラフィック",
      rateHint: "SSH 接続がゲートウェイ経由で送受信したバイト数（暗号化とパケットを含む）",
      total: "累計",
      sinceStart: "コアサービスの今回の起動以降",
      runTime: "実行時間",
      startedAt: (time) => `${time} に開始`,
      notTimed: "一時停止中や停止中は計測しません",
      path: "経路",
      pathHint: "このトラフィックは、このゲートウェイとその接続のトラフィックにも含まれます",
      via: (link, connection) => (
        <>
          {link}
          {connection === null ? " 経由" : `（${connection}）経由`}
        </>
      ),
    },
    queue: {
      title: "キュー",
      waiting: "ダウンロード待ち",
      truncated: "スキャンは 10,000 項目で停止しました。残りは次回のスキャンで一覧します",
      unfinished: "未完了",
      unfinishedHint: "以前に取得してまだ完了していないファイルを、先に続きからダウンロードします",
      connections: "接続",
      connectionsHint: "ゲートウェイ経由で開いている SSH 接続",
      connectionsOf: (open, max) => `${open}／${max}`,
      lastScan: "前回のスキャン",
      skipped: (count) => `${count} 項目を除外（フォルダー、リンク、フィルターで除外した名前）`,
      at: (relative, absolute) => `${relative}（${absolute}）`,
      sinceStart: "今回の起動以降",
      tally: (completed, failed, bytes) => `完了 ${completed} · 失敗 ${failed} · ${bytes}`,
      retrying: "再試行待ちのファイル",
    },
    history: {
      title: "ダウンロード履歴",
      reading: "ダウンロード履歴を読み込み中",
      failed: "ダウンロード履歴を読み込めません",
      of: (name) => `${name} のダウンロード履歴`,
      loading: "読み込み中",
      older: "以前の記録を読み込む",
      kept: (kept, names) => `保存：${kept}。${names}。`,
      none: "完了または失敗したファイルはまだありません。",
    },
    transfer: {
      namesOff: "このジョブはファイル名を記録しません",
      nameOff: " · ファイル名未記録",
      sizeUnknown: "サイズ不明",
      noProgress: (count) => `${count} 回進展なし`,
      remote: (path) => `リモート：${path}`,
    },
    log: {
      title: "ログ",
      failed: "ログを読み込めません",
      of: (name) => `${name} のログ（新しい順）`,
      none: "まだ記録はありません。",
    },
    settings: {
      connection: "接続",
      gatewayOwner: (name, state) => `接続「${name}」：${state}`,
      gatewayAddress: (name, port) => `${name}（127.0.0.1:${port}）`,
      loginHint: "パスワードと鍵のパスフレーズは鍵保管庫にだけ保存され、表示されません",
      privateKey: (file) => `秘密鍵 ${file}`,
      passphraseStored: "鍵のパスフレーズ保存済み",
      passwordStored: "パスワード保存済み",
      hostKey: "ホスト鍵",
      hostKeySeen: (algorithm, time) => `${algorithm} · ${time} の初回接続時に記録`,
      hostKeyFirst: "初回接続時に記録し、以後はその鍵だけを受け入れます",
      neverConnected: "未接続",
      folders: "フォルダー",
      source: "取得元",
      sourceHint: "リモート",
      work: "処理中",
      workHint: "ダウンロード中のファイルを UUID の名前でここに置きます",
      failed: "失敗",
      local: "ローカル",
      localHint: "途中までのファイルは中の .vpn-manager-partial にあります",
      title: "設定",
      concurrent: "同時接続数",
      attemptsHint: "連続して進展がなかった回数",
      attempts: (count) => `${count} 回`,
      backoff: (secs) => `${secs} 秒から`,
      scanInterval: (secs) => `${secs} 秒`,
      dotFiles: ". で始まるファイル",
      skipped: "除外",
      downloaded: "ダウンロードする",
      created: "作成日時",
      fileNames: "ファイル名",
      fileNamesOn: "ログと転送履歴にファイル名とパスを書き出します",
      fileNamesOff:
        "未完了のファイルは、続きからダウンロードできるよう完了するまでファイル名を保持します。ダウンロード中のファイルは名前をリアルタイムで表示します",
      kept: "保存",
      keptHint: "クリアした記録と期限切れの記録はデータベースに残りません",
    },
  },
});
