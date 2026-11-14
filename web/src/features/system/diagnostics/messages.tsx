// Text of the diagnostics report's two views of the System page: 診斷 (the checks, the owned resources, the
// databases) and 執行環境 (the processes, the disk, the host's clock, the programs, the files, metrics and SSH), with
// the report's actions and the words `model.ts` and `actions.ts` use for them. The checks' messages, errors, paths and
// file names come from the service and are shown as they arrive. A .tsx: a sentence carries markup
// (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** “1 thing”, “3 things”. */
function countEn(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

export const m = defineMessages({
  en: {
    actions: {
      rerun: "Run again",
      rerunning: "Diagnosing",
      download: "Download JSON",
      notLoaded: "The report has not loaded yet",
      menu: "Diagnostics report actions",
    },
    /** A check's status (an unknown one says the shared “Unknown”). */
    check: { ok: "OK", warning: "Warning", failed: "Failed" },
    /** The report's conclusion in one line. */
    headline: {
      none: "No check results",
      allFine: (count: number) => (count === 1 ? "The 1 check is fine" : `All ${count} checks are fine`),
      attention: (count: number) => `${countEn(count, "check needs", "checks need")} attention`,
    },
    verdict: {
      label: "Diagnostics verdict",
      /** `when`: relative ("3 minutes ago"). */
      generated: (when: string) => `Generated ${when}`,
      noSecrets: "The report holds no secrets, connection destinations or account numbers",
    },
    checks: {
      title: "Check results",
      description:
        "Each is derived from the actual state; what cannot be determined is listed as “Unknown”, never as OK.",
      attention: "Needs attention",
      attentionList: "Checks that need attention",
      fineList: "Checks that are OK",
      /** Read out before a check that is fine (its icon says it to the eye). */
      fineLead: "OK: ",
    },
    resources: {
      /** Places the inspection could not look at, and leftovers it found. */
      gaps: (gaps: number, items: number) =>
        `${countEn(gaps, "place", "places")} could not be checked${items ? `, ${countEn(items, "leftover item", "leftover items")}` : ""}`,
      leftovers: (items: number) => `Also ${countEn(items, "leftover item", "leftover items")}`,
      none: "No leftover processes, locks, sockets or temporary files",
      toRecovery: "Go to Recovery",
      incomplete: "Incomplete",
      inUse: (count: number) => `${count} in use`,
      running: (count: number) => `${count} running`,
      /** A worker after its connection's name. */
      worker: (generation: number, pid: number) => `generation ${generation} · pid ${pid}`,
      /** A Gateway's port, and that it refuses connections when it does. */
      port: (port: number, serving: boolean) => `${port}${serving ? "" : " (refusing connections)"}`,
    },
    databases: {
      title: "Databases",
      description:
        "Integrity is checked with PRAGMA quick_check; writes are refused while the queue is full (STORE_BUSY).",
      column: "Database",
      size: "Size",
      schema: "Schema",
      integrity: "Integrity",
      /** SQLite's quick_check found nothing wrong. */
      intact: "OK",
      queue: "Write queue",
      control: "Control",
      metrics: "Metrics",
      supported: (version: number) => `This version supports up to schema ${version}`,
      refusals: (count: number) => `refused ${countEn(count, "time", "times")}`,
    },
    view: {
      failed: "Cannot get the diagnostics report",
      generating: "Generating the diagnostics report",
      generatingDetail:
        "Generating the diagnostics report (checking database integrity, computing the programs' SHA-256)…",
      /** The report could not be refreshed: `time` is when the report shown was made. */
      stale: (time: string) => `Cannot update: showing the report from ${time}`,
      managerDown: "The core service (manager) cannot be reached; below is only the web service's data",
      noAnswer: "No response",
    },
    processes: {
      title: "Processes",
      role: { controller: "Web service", manager: "Core service" },
      uptime: "Running for",
      startUnknown: "Start time unknown",
      memory: "Memory",
      cpuTime: "CPU time",
      cpuSeconds: (seconds: string) => `${seconds} s`,
    },
    /** How long a process has run: 「3 天 4 小時」「12 分」. */
    duration: {
      days: (days: number, hours: number) => `${days} d ${hours} h`,
      hours: (hours: number, minutes: number) => `${hours} h ${minutes} min`,
      minutes: (minutes: number) => `${minutes} min`,
      seconds: (seconds: number) => `${seconds} s`,
    },
    /** A file or a reserve that is not there. */
    missing: "Does not exist",
    unreadable: "Unreadable",
    disk: {
      title: "Disk space",
      state: { normal: "Enough", low: "Low on space" },
      meter: "Usage of the disk holding the data directory",
      usage: (percent: number, free: string) => `${percent}% used, ${free} free`,
      /** `percent`: the used share as an element. */
      used: (percent: ReactNode): ReactNode => <>{percent} used</>,
      /** `free` and `total`: sizes as elements. */
      free: (free: ReactNode, total: ReactNode): ReactNode => (
        <>
          {free} free of {total}
        </>
      ),
      low: "Low-space threshold",
      lowHint:
        "Below it, the metrics database stops growing: new data is still saved, overwriting the oldest; control data and keys are never deleted",
      /** `when`: relative ("3 hours ago"). */
      lowSince: (when: string) => `Low since ${when}`,
      reserve: "Reserved space",
      reserveHint:
        "One per database, released when the disk fills up: the control-data reserve keeps stops and settings saveable; the metrics reserve keeps recording going",
      reserveOf: { control: "Control data", metrics: "Metrics" },
      held: "Held",
      released: "Released for writes when the disk filled up",
      pruned: "Data overwritten for space",
      prunedValue: (rows: number, skipped: number) =>
        `Oldest rows overwritten: ${rows} · samples not saved: ${skipped}`,
      lastFull: "Last full",
      error: "Error",
    },
    programs: {
      title: "Programs and versions",
      description: "The SHA-256 is that of the running program files; use it to compare with the installed version.",
      components: "Components",
      /** What a copy button copies. */
      sha256Of: (name: string) => `SHA-256 of ${name}`,
    },
    places: {
      title: "Locations and files",
      description: "Only sizes are listed; contents are never read.",
      socketDir: "Socket directory",
      vaultMatches: "The key on disk matches the key check recorded in the database",
      /** After the vault key's state: its file's size, or that it does not exist. */
      vaultFile: (size: string | null) => `; file ${size ?? "does not exist"}`,
      noLogFile: "This manager does not use --log-file (a development setup, for example)",
    },
    /** The vault key (vault.key) against the check the database records. */
    vaultKey: {
      matches: "Matches",
      mismatch: "Does not match",
      missing: "Missing",
      unsafe: "Wrong permissions",
    },
    activity: {
      title: "Metrics and SSH",
      description: "When metric writes fall behind, the charts show gaps rather than zeros.",
      writes: "Metric writes",
      written: (written: number, queued: number) => `Written ${written} · queued ${queued}`,
      dropped: (dropped: number, failures: number) => `Dropped ${dropped} · failed ${failures}`,
      clean: "Nothing dropped or failed",
      connections: "Connections",
      noConnections: "No connections",
      ssh: "SSH configuration",
      /** `reason`: why the hosts could not be read (the service's words). */
      hostsUnknown: (reason: string | null) => `Host count unknown (${reason ?? "unreadable"})`,
      hosts: (count: number) => countEn(count, "host", "hosts"),
      edited: "vpn-manager.conf was edited by hand",
      lastWriteFailed: (error: string) => `Last write failed: ${error}`,
      noSsh: "This manager does not have SSH Manager enabled",
    },
    /** The host's clock (執行環境). */
    clock: {
      title: "Clock",
      look: { synced: "Clock synchronized", notSynced: "Clock not synchronized", unknown: "Cannot tell" },
      hostTime: "Host time",
      versus: "Compared with this device",
      versusHint:
        "Computed from the time of the web service's latest answer; it can be off by about the time one response takes to arrive",
      notYet: "Not known yet",
      sync: "Time synchronization",
      synced: "Synchronized",
      notSynced:
        "Not synchronized: there is no time synchronization service such as NTP, or it has not synchronized yet",
      unknown: "Cannot tell (only judged on Linux)",
      /** Less than a second between the two clocks. */
      close: "Less than 1 s apart",
      /** `behind`: the host's clock is slower; `seconds`: how far, formatted. */
      skew: (behind: boolean, seconds: string) => `Host ${seconds} s ${behind ? "behind" : "ahead"}`,
      skewed: (skew: string) => `The host's clock differs from this device's: ${skew}`,
      /** What the gap means, and what to do about it by whether the host keeps its clock synchronized. */
      skewedBody: (synchronized: boolean | null | undefined) =>
        `Live figures are judged in the host's time and show as usual; data, records and expiry all follow the host's clock.${
          synchronized === false
            ? " The host has no time synchronization: enable it on the host, for example systemd-timesyncd or chrony."
            : synchronized === true
              ? " The host's clock is synchronized, so the gap most likely comes from this device's clock."
              : ""
        }`,
    },
  },
  "zh-TW": {
    actions: {
      rerun: "重新診斷",
      rerunning: "診斷中",
      download: "下載 JSON",
      notLoaded: "報告還沒有載入",
      menu: "診斷報告的操作",
    },
    check: { ok: "正常", warning: "警告", failed: "失敗" },
    headline: {
      none: "沒有檢查結果",
      allFine: (count) => `${count} 項檢查全部正常`,
      attention: (count) => `${count} 項需要注意`,
    },
    verdict: {
      label: "診斷結論",
      generated: (when) => `${when}產生`,
      noSecrets: "報告不含秘密、連線目的地與帳號號碼",
    },
    checks: {
      title: "檢查結果",
      description: "每一項都從實際狀態推得；無法判斷的列為「未知」，不當作正常。",
      attention: "需要注意",
      attentionList: "需要注意的檢查",
      fineList: "正常的檢查",
      fineLead: "正常：",
    },
    resources: {
      gaps: (gaps, items) => `有 ${gaps} 處無法檢查${items ? `、${items} 個遺留項目` : ""}`,
      leftovers: (items) => `另有 ${items} 個遺留項目`,
      none: "沒有遺留的程序、鎖、socket 或暫存檔",
      toRecovery: "前往恢復",
      incomplete: "不完整",
      inUse: (count) => `使用中 ${count}`,
      running: (count) => `執行中 ${count}`,
      worker: (generation, pid) => `第 ${generation} 代 · pid ${pid}`,
      port: (port, serving) => `${port}${serving ? "" : "（拒絕連線中）"}`,
    },
    databases: {
      title: "資料庫",
      description: "完整性用 PRAGMA quick_check；佇列滿時寫入會被拒絕（STORE_BUSY）。",
      column: "資料庫",
      size: "大小",
      schema: "schema",
      integrity: "完整性",
      intact: "正常",
      queue: "寫入佇列",
      control: "控制",
      metrics: "指標",
      supported: (version) => `這個版本支援到 schema ${version}`,
      refusals: (count) => `拒絕 ${count} 次`,
    },
    view: {
      failed: "無法取得診斷報告",
      generating: "正在產生診斷報告",
      generatingDetail: "正在產生診斷報告（檢查資料庫完整性、計算程式的 SHA-256）…",
      stale: (time) => `無法更新：顯示的是 ${time} 的報告`,
      managerDown: "核心服務（manager）無法連線，以下只有網頁服務的資料",
      noAnswer: "沒有回應",
    },
    processes: {
      title: "程序",
      role: { controller: "網頁服務", manager: "核心服務" },
      uptime: "已執行",
      startUnknown: "啟動時間未知",
      memory: "記憶體",
      cpuTime: "CPU 時間",
      cpuSeconds: (seconds) => `${seconds} 秒`,
    },
    duration: {
      days: (days, hours) => `${days} 天 ${hours} 小時`,
      hours: (hours, minutes) => `${hours} 小時 ${minutes} 分`,
      minutes: (minutes) => `${minutes} 分`,
      seconds: (seconds) => `${seconds} 秒`,
    },
    missing: "不存在",
    unreadable: "無法讀取",
    disk: {
      title: "磁碟空間",
      state: { normal: "充足", low: "空間不足" },
      meter: "資料目錄所在磁碟的使用量",
      usage: (percent, free) => `已用 ${percent}%，剩 ${free}`,
      used: (percent) => <>已用 {percent}</>,
      free: (free, total) => (
        <>
          剩 {free} / {total}
        </>
      ),
      low: "不足的界線",
      lowHint: "低於它時，指標資料庫不再變大：新的數據照常保存，覆蓋最舊的資料；控制資料與金鑰從不刪除",
      lowSince: (when) => `從 ${when}開始不足`,
      reserve: "預留空間",
      reserveHint: "各一份，磁碟寫滿時釋出：控制資料的讓停止與設定仍能寫入，指標的讓數據繼續記錄",
      reserveOf: { control: "控制資料", metrics: "指標" },
      held: "保留中",
      released: "已在磁碟滿時釋出給寫入",
      pruned: "為空間覆蓋的資料",
      prunedValue: (rows, skipped) => `覆蓋最舊的 ${rows} 筆 · 沒能保存的樣本 ${skipped}`,
      lastFull: "上次寫滿",
      error: "錯誤",
    },
    programs: {
      title: "程式與版本",
      description: "SHA-256 是執行中的程式檔案，可用來比對安裝的版本。",
      components: "元件",
      sha256Of: (name) => `${name} 的 SHA-256`,
    },
    places: {
      title: "位置與檔案",
      description: "只列大小，從不讀出內容。",
      socketDir: "socket 目錄",
      vaultMatches: "磁碟上的金鑰與資料庫記錄的金鑰檢查相符",
      vaultFile: (size) => `；檔案 ${size ?? "不存在"}`,
      noLogFile: "這個 manager 沒有使用 --log-file（例如開發環境）",
    },
    vaultKey: {
      matches: "相符",
      mismatch: "不相符",
      missing: "不見了",
      unsafe: "權限不對",
    },
    activity: {
      title: "指標與 SSH",
      description: "指標寫入落後時，圖表會出現缺口而不是補 0。",
      writes: "指標寫入",
      written: (written, queued) => `已寫入 ${written} · 佇列中 ${queued}`,
      dropped: (dropped, failures) => `丟棄 ${dropped} · 失敗 ${failures}`,
      clean: "沒有丟棄或失敗",
      connections: "連線",
      noConnections: "沒有連線",
      ssh: "SSH 設定",
      hostsUnknown: (reason) => `主機數未知（${reason ?? "無法讀取"}）`,
      hosts: (count) => `${count} 台主機`,
      edited: "vpn-manager.conf 被手動修改過",
      lastWriteFailed: (error) => `上次寫入失敗：${error}`,
      noSsh: "這個 manager 沒有啟用 SSH Manager",
    },
    clock: {
      title: "時間",
      look: { synced: "時間已同步", notSynced: "時間沒有同步", unknown: "無法判斷" },
      hostTime: "主機時間",
      versus: "與這台裝置",
      versusHint: "依網頁服務最近一次回答的時間計算，誤差約是一次回應的傳送時間",
      notYet: "尚未取得",
      sync: "時間同步",
      synced: "已同步",
      notSynced: "沒有同步：沒有 NTP 等時間同步服務，或還沒同步上",
      unknown: "無法判斷（只在 Linux 判斷）",
      close: "相差不到 1 秒",
      skew: (behind, seconds) => `主機${behind ? "慢" : "快"} ${seconds} 秒`,
      skewed: (skew) => `主機與這台裝置的時間不一致：${skew}`,
      skewedBody: (synchronized) =>
        `即時數據依主機的時間判斷，照常顯示；數據、紀錄與到期都照主機的時鐘。${
          synchronized === false
            ? "主機沒有時間同步：請在主機啟用，例如 systemd-timesyncd 或 chrony。"
            : synchronized === true
              ? "主機的時間已同步，差距多半來自這台裝置的時鐘。"
              : ""
        }`,
    },
  },
  ja: {
    actions: {
      rerun: "再診断",
      rerunning: "診断中",
      download: "JSON をダウンロード",
      notLoaded: "レポートはまだ読み込まれていません",
      menu: "診断レポートの操作",
    },
    check: { ok: "正常", warning: "警告", failed: "失敗" },
    headline: {
      none: "チェック結果がありません",
      allFine: (count) => `${count} 件のチェックはすべて正常です`,
      attention: (count) => `${count} 件が要注意です`,
    },
    verdict: {
      label: "診断の結論",
      generated: (when) => `生成：${when}`,
      noSecrets: "レポートには秘密情報、接続先、アカウント番号は含まれません",
    },
    checks: {
      title: "チェック結果",
      description: "各項目は実際の状態から導いたものです。判断できないものは「不明」とし、正常とはみなしません。",
      attention: "要注意",
      attentionList: "要注意のチェック",
      fineList: "正常なチェック",
      fineLead: "正常：",
    },
    resources: {
      gaps: (gaps, items) => `${gaps} か所をチェックできません${items ? `、残留項目 ${items} 件` : ""}`,
      leftovers: (items) => `ほかに残留項目が ${items} 件あります`,
      none: "残留したプロセス、ロック、ソケット、一時ファイルはありません",
      toRecovery: "復旧へ移動",
      incomplete: "不完全",
      inUse: (count) => `使用中 ${count}`,
      running: (count) => `実行中 ${count}`,
      worker: (generation, pid) => `第 ${generation} 世代 · pid ${pid}`,
      port: (port, serving) => `${port}${serving ? "" : "（接続を拒否中）"}`,
    },
    databases: {
      title: "データベース",
      description: "整合性は PRAGMA quick_check で確認します。キューが満杯の間は書き込みが拒否されます（STORE_BUSY）。",
      column: "データベース",
      size: "サイズ",
      schema: "スキーマ",
      integrity: "整合性",
      intact: "正常",
      queue: "書き込みキュー",
      control: "制御",
      metrics: "メトリクス",
      supported: (version) => `このバージョンはスキーマ ${version} まで対応しています`,
      refusals: (count) => `${count} 回拒否`,
    },
    view: {
      failed: "診断レポートを取得できません",
      generating: "診断レポートを生成しています",
      generatingDetail: "診断レポートを生成しています（データベースの整合性チェック、プログラムの SHA-256 の計算）…",
      stale: (time) => `更新できません：${time} 時点のレポートを表示しています`,
      managerDown: "コアサービス（manager）に接続できません。以下は Web サービスのデータのみです",
      noAnswer: "応答なし",
    },
    processes: {
      title: "プロセス",
      role: { controller: "Web サービス", manager: "コアサービス" },
      uptime: "稼働時間",
      startUnknown: "起動時刻不明",
      memory: "メモリ",
      cpuTime: "CPU 時間",
      cpuSeconds: (seconds) => `${seconds} 秒`,
    },
    duration: {
      days: (days, hours) => `${days} 日 ${hours} 時間`,
      hours: (hours, minutes) => `${hours} 時間 ${minutes} 分`,
      minutes: (minutes) => `${minutes} 分`,
      seconds: (seconds) => `${seconds} 秒`,
    },
    missing: "存在しません",
    unreadable: "読み取れません",
    disk: {
      title: "ディスク容量",
      state: { normal: "十分", low: "空き容量不足" },
      meter: "データディレクトリがあるディスクの使用量",
      usage: (percent, free) => `使用済み ${percent}%、残り ${free}`,
      used: (percent) => <>使用済み {percent}</>,
      free: (free, total) => (
        <>
          残り {free} / {total}
        </>
      ),
      low: "不足のしきい値",
      lowHint:
        "これを下回ると、メトリクスデータベースは大きくなりません。新しいデータは通常どおり保存され、最も古いデータを上書きします。制御データと鍵が削除されることはありません",
      lowSince: (when) => `${when}から不足`,
      reserve: "予約領域",
      reserveHint:
        "それぞれ 1 つずつあり、ディスクが満杯になると解放されます。制御データ用は停止や設定の書き込みを、メトリクス用はデータの記録を続けられるようにします",
      reserveOf: { control: "制御データ", metrics: "メトリクス" },
      held: "確保中",
      released: "ディスクが満杯になったときに書き込み用に解放済み",
      pruned: "容量確保のため上書きしたデータ",
      prunedValue: (rows, skipped) => `最も古い ${rows} 件を上書き · 保存できなかったサンプル ${skipped}`,
      lastFull: "前回満杯になった日時",
      error: "エラー",
    },
    programs: {
      title: "プログラムとバージョン",
      description: "SHA-256 は実行中のプログラムファイルのもので、インストールしたバージョンとの照合に使えます。",
      components: "コンポーネント",
      sha256Of: (name) => `${name} の SHA-256`,
    },
    places: {
      title: "場所とファイル",
      description: "サイズのみを表示し、内容は読み出しません。",
      socketDir: "ソケットディレクトリ",
      vaultMatches: "ディスク上の鍵は、データベースに記録された鍵のチェックと一致します",
      vaultFile: (size) => `。ファイル：${size ?? "なし"}`,
      noLogFile: "この manager は --log-file を使用していません（開発環境など）",
    },
    vaultKey: {
      matches: "一致",
      mismatch: "不一致",
      missing: "見つかりません",
      unsafe: "権限が不正",
    },
    activity: {
      title: "メトリクスと SSH",
      description: "メトリクスの書き込みが遅れると、グラフは 0 で埋めずに欠落として表示します。",
      writes: "メトリクスの書き込み",
      written: (written, queued) => `書き込み済み ${written} · キュー内 ${queued}`,
      dropped: (dropped, failures) => `破棄 ${dropped} · 失敗 ${failures}`,
      clean: "破棄や失敗はありません",
      connections: "接続",
      noConnections: "接続はありません",
      ssh: "SSH 設定",
      hostsUnknown: (reason) => `ホスト数不明（${reason ?? "読み取れません"}）`,
      hosts: (count) => `${count} 台のホスト`,
      edited: "vpn-manager.conf は手動で変更されています",
      lastWriteFailed: (error) => `前回の書き込みに失敗：${error}`,
      noSsh: "この manager では SSH Manager が有効になっていません",
    },
    clock: {
      title: "時刻",
      look: { synced: "時刻同期済み", notSynced: "時刻が同期されていません", unknown: "判断できません" },
      hostTime: "ホストの時刻",
      versus: "このデバイスとの差",
      versusHint: "Web サービスの直近の応答の時刻から計算します。誤差は応答 1 回の転送時間程度です",
      notYet: "未取得",
      sync: "時刻同期",
      synced: "同期済み",
      notSynced: "同期されていません：NTP などの時刻同期サービスがないか、まだ同期できていません",
      unknown: "判断できません（Linux でのみ判断します）",
      close: "差は 1 秒未満",
      skew: (behind, seconds) => `ホストが ${seconds} 秒${behind ? "遅れています" : "進んでいます"}`,
      skewed: (skew) => `ホストとこのデバイスの時刻が一致しません：${skew}`,
      skewedBody: (synchronized) =>
        `リアルタイムの数値はホストの時刻で判断し、通常どおり表示します。データ、記録、期限はすべてホストの時計に従います。${
          synchronized === false
            ? "ホストで時刻同期が行われていません。ホストで systemd-timesyncd や chrony などを有効にしてください。"
            : synchronized === true
              ? "ホストの時刻は同期されているため、差はおそらくこのデバイスの時計によるものです。"
              : ""
        }`,
    },
  },
});
