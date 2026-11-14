// Text of the SSH downloads page (SSH 下載): the list of jobs, a job's states, steps and filters as words, its actions,
// what sending them reports and the confirmations behind them, and the labels the dialog and the inspector share. The
// job dialog's text is in dialog/messages.ts and the inspector's in inspector/messages.tsx. The page's title is the
// section name (components/shell/messages.ts, `nav.sshDownloads`). Job names, file names, paths and the service's
// reasons are shown as they arrive.

import { defineMessages } from "@/i18n";

/** "file" or "files", by the count. */
const files = (count: number) => (count === 1 ? "file" : "files");

export const m = defineMessages({
  en: {
    page: {
      description: "Download new files from a remote folder over SFTP automatically, only through the VPN.",
      help: "Each job lists the remote source folder at intervals, moves each file to the working folder and downloads it (resuming where it stopped), and deletes the remote file only once it is in the local folder; a file that makes no progress several times is moved to the failed folder. Every connection goes through the tunnel of the connection the chosen Gateway belongs to, and the server's name is resolved inside the tunnel too; while the connection is not ready the job waits and never falls back to the ordinary network.",
      helpText:
        "Every connection goes only through the chosen Gateway's VPN; while the connection is not ready the job waits and never falls back to the ordinary network.",
      /** The page's primary action, and the title of the dialog it opens. */
      add: "Add download job",
      readingGateways: "Reading the Gateways…",
      needsGateway: "Create a SOCKS5 or Mixed Gateway first: downloads go only through its VPN connection",
    },
    list: {
      loading: "Loading download jobs",
      emptyTitle: "No download jobs yet",
      emptyNeedsGateway:
        "Downloads go only through a Gateway's VPN connection: create a SOCKS5 or Mixed Gateway first.",
      emptyBody:
        "Checks a remote folder at intervals and downloads new files to a local folder over SFTP; every connection goes only through the VPN of the Gateway you choose.",
      toolbar: "Download job list",
      search: "Search download jobs",
      searchPlaceholder: "Name, host or folder",
      /** After the count: "3 download jobs", "Showing 2/3 download jobs". */
      unit: (count: number): string => (count === 1 ? "download job" : "download jobs"),
      stale: (time: string) => `Cannot update: showing the data of ${time}`,
      table: "Download jobs",
      progress: "Progress",
      noMatch: "No download job matches",
      detailsOf: (name: string) => `Details of ${name}`,
      details: "Download job details",
      notFound: "This download job was not found",
      select: "Select a download job",
      selectHint: "See the files in progress, the queue, the download history and the log.",
      /** A row's work: how many files are in flight, and how many more wait. */
      files: (count: number) => `${count} ${files(count)}`,
      alsoQueued: (count: number) => ` · ${count} more waiting`,
      queued: (count: number) => `${count} ${files(count)} waiting`,
      unfinished: (count: number) => `${count} unfinished`,
      noNewFiles: "No new files",
      notScanned: "Not scanned yet",
      /** Bytes done of the bytes known, as one value. */
      bytesOf: (done: string, total: string) => `${done} / ${total}`,
      /** The tooltip of a running job's SSH traffic. */
      wire: (rx: string, tx: string) => `SSH traffic: download ${rx}, upload ${tx}`,
    },
    /** The progress bar of one file (its name) or of a job's files in flight (the job's name). */
    progressOf: (name: string) => `Download progress of ${name}`,
    rate: "Rate",
    onlyVpn: "Only through the VPN",
    /** A job's state, as the manager reports it. */
    state: {
      paused: "Paused",
      waiting_vpn: "Waiting for VPN",
      connecting: "Connecting",
      scanning: "Scanning",
      downloading: "Downloading",
      idle: "Waiting for new files",
      retrying: "Retrying later",
      error: "Needs attention",
    },
    /** The step a file in flight is at. */
    step: {
      claiming: "Moving to the working folder",
      downloading: "Downloading",
      finalizing: "Placing in the local folder",
      failing: "Moving to the failed folder",
    },
    /** A transfer's state in the history and the retry queue. */
    transfer: {
      claiming: "Claiming",
      downloading: "Unfinished",
      finalizing: "Placing",
      local_done: "Deleting the remote copy",
      failing: "Moving to failed",
      completed: "Completed",
      failed: "Failed",
    },
    /** Which file names a job downloads; the first one's title is the shared word for “all”. */
    nameFilter: {
      all: { text: "Every regular file in the source folder" },
      skip_uuid: {
        title: "Skip UUID names",
        text: "Skip files whose name contains a UUID (temporary names of uploads in progress; IS_FILTER_UUID_FILE in the original tool)",
      },
      only_uuid: { title: "Only UUID names", text: "Download only files whose name contains a UUID" },
    },
    /** The list's state filter: what each choice holds. */
    filter: {
      allTitle: "All download jobs",
      runningTitle:
        "Jobs that are not paused: downloading, scanning, waiting for new files, waiting for VPN or retrying later",
      pausedTitle: "Jobs the user paused",
      attentionTitle: "Stopped jobs: the host key changed, the login was refused or the local folder cannot be used",
    },
    sort: { created: "Created" },
    /** A remaining or elapsed time. */
    duration: {
      seconds: (secs: number) => `${secs} s`,
      minutes: (mins: number, secs: number) => `${mins} min ${secs} s`,
      hours: (hours: number, mins: number) => `${hours} h ${mins} min`,
    },
    /** One file's progress: bytes done of its size, and the percentage. */
    progress: (done: string, total: string, percent: number) => `${done} / ${total} (${percent}%)`,
    /** A job's record settings: whether file names are kept, and for how long the log and history are. */
    records: {
      names: "File names recorded",
      noNames: "File names not recorded (transfer numbers only)",
      newest: "The newest 500 log lines and 1,000 records",
      days: (days: number) => `${days} ${days === 1 ? "day" : "days"} (at most 500 log lines and 1,000 records)`,
    },
    /** Labels the dialog and the inspector share. */
    field: {
      gateway: "Gateway",
      server: "Server",
      login: "Login",
      attempts: "Attempts",
      backoff: "Retry interval",
      backoffHint: "Doubles each time, up to 10 minutes",
      scanInterval: "Scan interval",
      nameFilter: "File name filter",
      records: "Records",
    },
    action: {
      pause: "Pause",
      pausing: "Pausing",
      resume: "Resume",
      resuming: "Resuming",
      retry: "Retry",
      retrying: "Retrying",
      scan: "Scan now",
      trust: "Trust the new host key…",
      openGateway: "Go to the Gateway",
      clearHistory: "Clear transfer history…",
      clearLog: "Clear log…",
      clearing: "Clearing",
      /** Why an action cannot run now. */
      sending: (action: string) => `“${action}” is being sent; wait until it is done`,
      paused: "The job is paused; press “Resume” first",
      stopped: "The job has stopped: deal with the problem above first",
      unknown: "State unknown (the core service is not connected)",
      noOfferedKey: "The server has not offered a different host key",
      gatewayMissing: "This Gateway was not found",
    },
    /** The name of each intent while it is on its way. */
    verb: {
      pause: "Pause",
      resume: "Resume",
      scan: "Scan now",
      trust_host_key: "Trust the new host key",
      clear_log: "Clear log",
      clear_history: "Clear transfer history",
    },
    /** What was attempted, for the report of a failure: the notification adds that it failed. */
    intent: {
      pause: (name: string) => `Pause ${name}`,
      resume: (name: string) => `Resume ${name}`,
      scan: (name: string) => `Scan ${name} now`,
      trust_host_key: (name: string) => `Trust the new host key of ${name}`,
      clear_log: (name: string) => `Clear the log of ${name}`,
      clear_history: (name: string) => `Clear the transfer history of ${name}`,
      delete: (name: string) => `Delete ${name}`,
    },
    /** What an accepted intent reports. */
    sent: {
      paused: (name: string) => `Paused ${name}`,
      pausedUnfinished: (count: number) =>
        count === 1
          ? "The unfinished file continues downloading once the job resumes."
          : `The ${count} unfinished files continue downloading once the job resumes.`,
      resumed: (name: string) => `Resumed ${name}`,
      vpnOnly: "It connects only through the Gateway's VPN, and waits while the VPN is not ready.",
      scanning: (name: string) => `Scanning the source folder of ${name}`,
      scanningDetail: "New files it finds are downloaded in turn.",
      trusted: (name: string) => `Trusted the new host key of ${name}`,
      logCleared: (name: string, count: number) =>
        `Cleared the log of ${name} (${count} ${count === 1 ? "line" : "lines"})`,
      historyCleared: (name: string, count: number) =>
        `Cleared the transfer history of ${name} (${count} ${count === 1 ? "record" : "records"})`,
      keepsUnfinished: "Unfinished files keep their records and continue downloading.",
      deleted: (name: string) => `Deleted download job ${name}`,
    },
    deleteConfirm: {
      title: (name: string) => `Delete the download job “${name}”?`,
      body: (localDir: string) =>
        `The job stops, and its settings, download history, log and stored passwords are deleted with it. Files already downloaded to ${localDir} are not affected.`,
      unfinished: (count: number, workDir: string) =>
        count === 1
          ? `1 file is not finished: it stays in the remote working folder (${workDir}) and is not deleted; its partial local copy is deleted.`
          : `${count} files are not finished: they stay in the remote working folder (${workDir}) and are not deleted; their partial local copies are deleted.`,
    },
    clearConfirm: {
      logTitle: (name: string) => `Clear the log of “${name}”?`,
      historyTitle: (name: string) => `Clear the transfer history of “${name}”?`,
      logBody:
        "Every log line of this job is deleted for good, and nothing of it stays in the database; afterwards a single line says the log was cleared.",
      historyBody:
        "This job's records of completed and failed transfers (file names, paths, sizes and reasons) are deleted for good, and nothing of them stays in the database.",
      keepsUnfinished: (count: number) =>
        count === 1
          ? "The unfinished file keeps its record: it continues downloading where it stopped and appears in the history once it finishes."
          : `The ${count} unfinished files keep their records: they continue downloading where they stopped and appear in the history once they finish.`,
      untouchedLog: (localDir: string) =>
        `No file is deleted or moved (${localDir} on this computer and the remote folders stay as they are); the transfer history is not affected either.`,
      untouchedHistory: (localDir: string) =>
        `No file is deleted or moved (${localDir} on this computer and the remote folders stay as they are); the log is not affected either.`,
      cannotBeUndone: "This cannot be undone.",
    },
    trustConfirm: {
      title: "Trust the new host key?",
      confirm: "Trust and resume",
      body: (host: string, port: number) =>
        `The host key ${host}:${port} offers differs from the recorded one. A reinstalled server causes this, and so does someone intercepting the connection: check the fingerprint another way first (for example by running ssh-keygen -lf on the server).`,
      recorded: "Recorded",
      offered: "Offered now",
      /** A host key: its fingerprint and algorithm. */
      key: (fingerprint: string, algorithm: string) => `${fingerprint} (${algorithm})`,
      checked: "I have checked that the server's fingerprint is the one “Offered now”",
      checkFirst: "Tick the box to trust it; only the key shown above is trusted.",
    },
  },
  "zh-TW": {
    page: {
      description: "從遠端資料夾經 SFTP 自動下載新檔案，只經 VPN。",
      help: "每個工作定期列出遠端的來源資料夾，把檔案移到處理中資料夾後下載（可從中斷處接續），放進本機資料夾後才刪除遠端的檔案；多次沒有進展的檔案移到失敗資料夾。所有連線都經選定代理埠所屬連線的 tunnel，伺服器名稱也在 tunnel 內解析；連線沒有就緒時工作會等待，不會改走一般網路。",
      helpText: "所有連線只經選定代理埠的 VPN；連線沒有就緒時工作會等待，不會改走一般網路。",
      add: "新增下載工作",
      readingGateways: "正在讀取代理埠…",
      needsGateway: "先建立一個 SOCKS5 或 Mixed 代理埠：下載只經它的 VPN 連線",
    },
    list: {
      loading: "載入下載工作",
      emptyTitle: "還沒有下載工作",
      emptyNeedsGateway: "下載只經代理埠的 VPN 連線：先建立一個 SOCKS5 或 Mixed 代理埠。",
      emptyBody: "定期查看遠端資料夾，經 SFTP 把新檔案下載到本機資料夾；所有連線只經你選的代理埠的 VPN。",
      toolbar: "下載工作清單",
      search: "搜尋下載工作",
      searchPlaceholder: "名稱、主機或資料夾",
      unit: () => "個下載工作",
      stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
      table: "下載工作",
      progress: "進度",
      noMatch: "沒有符合條件的下載工作",
      detailsOf: (name) => `${name} 的詳細資料`,
      details: "下載工作詳細資料",
      notFound: "找不到這個下載工作",
      select: "選擇一個下載工作",
      selectHint: "查看進行中的檔案、佇列、下載紀錄與日誌。",
      files: (count) => `${count} 個檔案`,
      alsoQueued: (count) => ` · 另有 ${count} 個等待`,
      queued: (count) => `${count} 個檔案等待`,
      unfinished: (count) => `${count} 個未完成`,
      noNewFiles: "沒有新檔案",
      notScanned: "尚未掃描",
      bytesOf: (done, total) => `${done}／${total}`,
      wire: (rx, tx) => `SSH 流量：下載 ${rx}，上傳 ${tx}`,
    },
    progressOf: (name) => `${name} 的下載進度`,
    rate: "速率",
    onlyVpn: "只經 VPN",
    state: {
      paused: "已暫停",
      waiting_vpn: "等待 VPN",
      connecting: "連線中",
      scanning: "掃描中",
      downloading: "下載中",
      idle: "等待新檔案",
      retrying: "稍後重試",
      error: "需要處理",
    },
    step: {
      claiming: "移到處理中資料夾",
      downloading: "下載中",
      finalizing: "放入本機資料夾",
      failing: "移到失敗資料夾",
    },
    transfer: {
      claiming: "認領中",
      downloading: "未完成",
      finalizing: "放入中",
      local_done: "刪除遠端中",
      failing: "移到失敗中",
      completed: "完成",
      failed: "失敗",
    },
    nameFilter: {
      all: { text: "來源資料夾裡的每個一般檔案" },
      skip_uuid: {
        title: "略過含 UUID",
        text: "略過名稱含 UUID 的檔案（上傳中的暫存名稱；原工具的 IS_FILTER_UUID_FILE）",
      },
      only_uuid: { title: "只要含 UUID", text: "只下載名稱含 UUID 的檔案" },
    },
    filter: {
      allTitle: "所有下載工作",
      runningTitle: "沒有暫停的工作：下載、掃描、等待新檔案、等待 VPN 或稍後重試",
      pausedTitle: "使用者暫停的工作",
      attentionTitle: "停止中的工作：主機金鑰改變、登入被拒或本機資料夾無法使用",
    },
    sort: { created: "建立時間" },
    duration: {
      seconds: (secs) => `${secs} 秒`,
      minutes: (mins, secs) => `${mins} 分 ${secs} 秒`,
      hours: (hours, mins) => `${hours} 小時 ${mins} 分`,
    },
    progress: (done, total, percent) => `${done}／${total}（${percent}%）`,
    records: {
      names: "記錄檔名",
      noNames: "不記錄檔名（只留傳輸編號）",
      newest: "最新的 500 行日誌與 1,000 筆紀錄",
      days: (days) => `${days} 天（最多 500 行日誌與 1,000 筆紀錄）`,
    },
    field: {
      gateway: "代理埠",
      server: "伺服器",
      login: "登入",
      attempts: "嘗試次數",
      backoff: "重試間隔",
      backoffHint: "每次加倍，最長 10 分鐘",
      scanInterval: "掃描間隔",
      nameFilter: "檔名篩選",
      records: "紀錄",
    },
    action: {
      pause: "暫停",
      pausing: "暫停中",
      resume: "繼續",
      resuming: "繼續中",
      retry: "重試",
      retrying: "重試中",
      scan: "立即掃描",
      trust: "信任新的主機金鑰…",
      openGateway: "前往代理埠",
      clearHistory: "清除傳輸紀錄…",
      clearLog: "清除日誌…",
      clearing: "清除中",
      sending: (action) => `正在送出「${action}」，完成後再操作`,
      paused: "工作已暫停；先按「繼續」",
      stopped: "工作已停止：先處理上方的問題",
      unknown: "狀態未知（核心服務未連線）",
      noOfferedKey: "伺服器沒有提供不同的主機金鑰",
      gatewayMissing: "找不到這個代理埠",
    },
    verb: {
      pause: "暫停",
      resume: "繼續",
      scan: "立即掃描",
      trust_host_key: "信任新的主機金鑰",
      clear_log: "清除日誌",
      clear_history: "清除傳輸紀錄",
    },
    intent: {
      pause: (name) => `暫停 ${name}`,
      resume: (name) => `繼續 ${name}`,
      scan: (name) => `立即掃描 ${name}`,
      trust_host_key: (name) => `信任新的主機金鑰 ${name}`,
      clear_log: (name) => `清除日誌 ${name}`,
      clear_history: (name) => `清除傳輸紀錄 ${name}`,
      delete: (name) => `刪除 ${name}`,
    },
    sent: {
      paused: (name) => `已暫停 ${name}`,
      pausedUnfinished: (count) => `未完成的 ${count} 個檔案會在繼續後接著下載。`,
      resumed: (name) => `已繼續 ${name}`,
      vpnOnly: "只經代理埠的 VPN 連線；VPN 未就緒時會等待。",
      scanning: (name) => `正在掃描 ${name} 的來源資料夾`,
      scanningDetail: "找到的新檔案會依序下載。",
      trusted: (name) => `已信任 ${name} 的新主機金鑰`,
      logCleared: (name, count) => `已清除 ${name} 的日誌（${count} 行）`,
      historyCleared: (name, count) => `已清除 ${name} 的傳輸紀錄（${count} 筆）`,
      keepsUnfinished: "未完成的檔案保留紀錄，會接著下載。",
      deleted: (name) => `已刪除下載工作 ${name}`,
    },
    deleteConfirm: {
      title: (name) => `刪除下載工作「${name}」？`,
      body: (localDir) =>
        `工作會停止，它的設定、下載紀錄、日誌與儲存的密碼一起刪除。已經下載到 ${localDir} 的檔案不受影響。`,
      unfinished: (count, workDir) =>
        `還有 ${count} 個檔案沒有完成：它們留在遠端的處理中資料夾（${workDir}），不會被刪除；本機的部分檔案會刪除。`,
    },
    clearConfirm: {
      logTitle: (name) => `清除「${name}」的日誌？`,
      historyTitle: (name) => `清除「${name}」的傳輸紀錄？`,
      logBody: "這個工作的所有日誌都會永久刪除，資料庫裡不留內容；之後只有一行說明日誌已清除。",
      historyBody: "這個工作已完成與失敗的傳輸紀錄（檔名、路徑、大小與原因）都會永久刪除，資料庫裡不留內容。",
      keepsUnfinished: (count) => `未完成的 ${count} 個檔案保留紀錄：它們會從中斷處接著下載，完成後再出現在紀錄中。`,
      untouchedLog: (localDir) =>
        `不會刪除或移動任何檔案（本機的 ${localDir}、遠端的資料夾都不變）；傳輸紀錄也不受影響。`,
      untouchedHistory: (localDir) =>
        `不會刪除或移動任何檔案（本機的 ${localDir}、遠端的資料夾都不變）；日誌也不受影響。`,
      cannotBeUndone: "清除後無法復原。",
    },
    trustConfirm: {
      title: "信任新的主機金鑰？",
      confirm: "信任並繼續",
      body: (host, port) =>
        `${host}:${port} 提供的主機金鑰和記錄的不同。伺服器重新安裝會這樣，有人攔截連線也會這樣：請先用其他方式（例如在伺服器上執行 ssh-keygen -lf）核對指紋。`,
      recorded: "記錄的",
      offered: "現在提供",
      key: (fingerprint, algorithm) => `${fingerprint}（${algorithm}）`,
      checked: "我已核對伺服器的指紋就是「現在提供」的這一個",
      checkFirst: "勾選後才能信任；只會信任上面顯示的這把金鑰。",
    },
  },
  ja: {
    page: {
      description: "リモートフォルダーから SFTP で新しいファイルを自動ダウンロードします。VPN だけを経由します。",
      help: "各ジョブはリモートの取得元フォルダーを定期的に一覧し、ファイルを処理中フォルダーに移動してからダウンロードします（中断したところから再開できます）。ローカルフォルダーに配置してから、リモートのファイルを削除します。何度も進展がなかったファイルは失敗フォルダーに移動します。すべての接続は、選んだゲートウェイが属する接続のトンネルを通り、サーバー名もトンネル内で名前解決します。接続の準備ができていない間、ジョブは待機し、通常のネットワークには切り替わりません。",
      helpText:
        "すべての接続は、選んだゲートウェイの VPN だけを通ります。接続の準備ができていない間、ジョブは待機し、通常のネットワークには切り替わりません。",
      add: "ダウンロードジョブを追加",
      readingGateways: "ゲートウェイを読み込んでいます…",
      needsGateway:
        "先に SOCKS5 または Mixed のゲートウェイを作成してください。ダウンロードはその VPN 接続だけを通ります",
    },
    list: {
      loading: "ダウンロードジョブを読み込み中",
      emptyTitle: "ダウンロードジョブはまだありません",
      emptyNeedsGateway:
        "ダウンロードはゲートウェイの VPN 接続だけを通ります。先に SOCKS5 または Mixed のゲートウェイを作成してください。",
      emptyBody:
        "リモートフォルダーを定期的に確認し、新しいファイルを SFTP でローカルフォルダーにダウンロードします。すべての接続は、選んだゲートウェイの VPN だけを通ります。",
      toolbar: "ダウンロードジョブ一覧",
      search: "ダウンロードジョブを検索",
      searchPlaceholder: "名前、ホスト、フォルダー",
      unit: () => "件のダウンロードジョブ",
      stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
      table: "ダウンロードジョブ",
      progress: "進捗",
      noMatch: "条件に一致するダウンロードジョブはありません",
      detailsOf: (name) => `${name} の詳細`,
      details: "ダウンロードジョブの詳細",
      notFound: "このダウンロードジョブが見つかりません",
      select: "ダウンロードジョブを選択",
      selectHint: "進行中のファイル、キュー、ダウンロード履歴、ログを確認できます。",
      files: (count) => `${count} 件のファイル`,
      alsoQueued: (count) => ` · ほかに ${count} 件が待機中`,
      queued: (count) => `${count} 件のファイルが待機中`,
      unfinished: (count) => `${count} 件が未完了`,
      noNewFiles: "新しいファイルなし",
      notScanned: "未スキャン",
      bytesOf: (done, total) => `${done}／${total}`,
      wire: (rx, tx) => `SSH トラフィック：ダウンロード ${rx}、アップロード ${tx}`,
    },
    progressOf: (name) => `${name} のダウンロード進捗`,
    rate: "速度",
    onlyVpn: "VPN 経由のみ",
    state: {
      paused: "一時停止",
      waiting_vpn: "VPN 待ち",
      connecting: "接続中",
      scanning: "スキャン中",
      downloading: "ダウンロード中",
      idle: "新しいファイル待ち",
      retrying: "後で再試行",
      error: "要対応",
    },
    step: {
      claiming: "処理中フォルダーへ移動",
      downloading: "ダウンロード中",
      finalizing: "ローカルフォルダーへ配置",
      failing: "失敗フォルダーへ移動",
    },
    transfer: {
      claiming: "確保中",
      downloading: "未完了",
      finalizing: "配置中",
      local_done: "リモート側を削除中",
      failing: "失敗フォルダーへ移動中",
      completed: "完了",
      failed: "失敗",
    },
    nameFilter: {
      all: { text: "取得元フォルダー内のすべての通常ファイル" },
      skip_uuid: {
        title: "UUID 入りを除外",
        text: "名前に UUID を含むファイルを除外します（アップロード中の一時的な名前。元のツールの IS_FILTER_UUID_FILE）",
      },
      only_uuid: { title: "UUID 入りのみ", text: "名前に UUID を含むファイルだけをダウンロードします" },
    },
    filter: {
      allTitle: "すべてのダウンロードジョブ",
      runningTitle: "一時停止していないジョブ：ダウンロード中、スキャン中、新しいファイル待ち、VPN 待ち、後で再試行",
      pausedTitle: "ユーザーが一時停止したジョブ",
      attentionTitle: "停止しているジョブ：ホスト鍵の変更、ログインの拒否、ローカルフォルダーが使えない",
    },
    sort: { created: "作成日時" },
    duration: {
      seconds: (secs) => `${secs} 秒`,
      minutes: (mins, secs) => `${mins} 分 ${secs} 秒`,
      hours: (hours, mins) => `${hours} 時間 ${mins} 分`,
    },
    progress: (done, total, percent) => `${done}／${total}（${percent}%）`,
    records: {
      names: "ファイル名を記録",
      noNames: "ファイル名を記録しない（転送番号のみ）",
      newest: "最新のログ 500 行と記録 1,000 件",
      days: (days) => `${days} 日（最大でログ 500 行と記録 1,000 件）`,
    },
    field: {
      gateway: "ゲートウェイ",
      server: "サーバー",
      login: "ログイン",
      attempts: "試行回数",
      backoff: "再試行の間隔",
      backoffHint: "毎回 2 倍になり、最長 10 分です",
      scanInterval: "スキャン間隔",
      nameFilter: "ファイル名フィルター",
      records: "記録",
    },
    action: {
      pause: "一時停止",
      pausing: "一時停止中",
      resume: "再開",
      resuming: "再開中",
      retry: "再試行",
      retrying: "再試行中",
      scan: "今すぐスキャン",
      trust: "新しいホスト鍵を信頼…",
      openGateway: "ゲートウェイへ移動",
      clearHistory: "転送履歴をクリア…",
      clearLog: "ログをクリア…",
      clearing: "クリア中",
      sending: (action) => `「${action}」を送信中です。完了してから操作してください`,
      paused: "ジョブは一時停止中です。先に「再開」を押してください",
      stopped: "ジョブは停止しています。先に上の問題に対処してください",
      unknown: "状態不明（コアサービスに未接続）",
      noOfferedKey: "サーバーは別のホスト鍵を提示していません",
      gatewayMissing: "このゲートウェイが見つかりません",
    },
    verb: {
      pause: "一時停止",
      resume: "再開",
      scan: "今すぐスキャン",
      trust_host_key: "新しいホスト鍵を信頼",
      clear_log: "ログをクリア",
      clear_history: "転送履歴をクリア",
    },
    intent: {
      pause: (name) => `${name} の一時停止`,
      resume: (name) => `${name} の再開`,
      scan: (name) => `${name} のスキャン`,
      trust_host_key: (name) => `${name} の新しいホスト鍵の信頼`,
      clear_log: (name) => `${name} のログのクリア`,
      clear_history: (name) => `${name} の転送履歴のクリア`,
      delete: (name) => `${name} の削除`,
    },
    sent: {
      paused: (name) => `${name} を一時停止しました`,
      pausedUnfinished: (count) => `未完了の ${count} 件のファイルは、再開後に続きからダウンロードされます。`,
      resumed: (name) => `${name} を再開しました`,
      vpnOnly: "ゲートウェイの VPN 経由でのみ接続します。VPN の準備ができていないときは待機します。",
      scanning: (name) => `${name} の取得元フォルダーをスキャンしています`,
      scanningDetail: "見つかった新しいファイルは順番にダウンロードされます。",
      trusted: (name) => `${name} の新しいホスト鍵を信頼しました`,
      logCleared: (name, count) => `${name} のログをクリアしました（${count} 行）`,
      historyCleared: (name, count) => `${name} の転送履歴をクリアしました（${count} 件）`,
      keepsUnfinished: "未完了のファイルは記録が残り、続きからダウンロードされます。",
      deleted: (name) => `ダウンロードジョブ ${name} を削除しました`,
    },
    deleteConfirm: {
      title: (name) => `ダウンロードジョブ「${name}」を削除しますか？`,
      body: (localDir) =>
        `ジョブは停止し、その設定、ダウンロード履歴、ログ、保存したパスワードがまとめて削除されます。${localDir} にダウンロード済みのファイルには影響しません。`,
      unfinished: (count, workDir) =>
        `完了していないファイルが ${count} 件あります。これらはリモートの処理中フォルダー（${workDir}）に残り、削除されません。ローカルの途中までのファイルは削除されます。`,
    },
    clearConfirm: {
      logTitle: (name) => `「${name}」のログをクリアしますか？`,
      historyTitle: (name) => `「${name}」の転送履歴をクリアしますか？`,
      logBody:
        "このジョブのログはすべて完全に削除され、データベースに内容は残りません。その後は、ログをクリアしたことを示す 1 行だけが残ります。",
      historyBody:
        "このジョブの完了・失敗した転送履歴（ファイル名、パス、サイズ、理由）はすべて完全に削除され、データベースに内容は残りません。",
      keepsUnfinished: (count) =>
        `未完了の ${count} 件のファイルは記録が残ります。中断したところから続きをダウンロードし、完了すると履歴に表示されます。`,
      untouchedLog: (localDir) =>
        `ファイルの削除や移動は一切ありません（ローカルの ${localDir}、リモートのフォルダーはそのままです）。転送履歴にも影響しません。`,
      untouchedHistory: (localDir) =>
        `ファイルの削除や移動は一切ありません（ローカルの ${localDir}、リモートのフォルダーはそのままです）。ログにも影響しません。`,
      cannotBeUndone: "クリアすると元に戻せません。",
    },
    trustConfirm: {
      title: "新しいホスト鍵を信頼しますか？",
      confirm: "信頼して再開",
      body: (host, port) =>
        `${host}:${port} が提示したホスト鍵は、記録されているものと異なります。サーバーを再インストールした場合のほか、誰かが接続を傍受している場合にも起こります。先に別の方法（たとえばサーバー上で ssh-keygen -lf を実行する）で指紋を照合してください。`,
      recorded: "記録済み",
      offered: "今回の提示",
      key: (fingerprint, algorithm) => `${fingerprint}（${algorithm}）`,
      checked: "サーバーの指紋が「今回の提示」のものと一致することを確認しました",
      checkFirst: "チェックを入れると信頼できます。信頼するのは上に表示した鍵だけです。",
    },
  },
});
