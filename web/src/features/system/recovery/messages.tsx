// Text of the System page's 恢復 view: the inspection's conclusion and actions, the leftovers it found and what
// cleaning them does, what the manager holds, the confirmation and the result of a cleanup, and the words `model.ts`
// and `actions.ts` use for them. A leftover's title, detail, path and action, and what a cleanup did to it, come from
// the service and are shown as they arrive. A .tsx: a sentence carries markup (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** “1 item”, “3 items”. */
function itemsEn(count: number): string {
  return `${count} ${count === 1 ? "item" : "items"}`;
}

export const m = defineMessages({
  en: {
    actions: {
      recheck: "Check again",
      clean: "Clean up",
      cleaning: "Cleaning up",
      /** Every cleanable leftover at once, by how many. */
      cleanCount: (count: number) => `Clean up ${itemsEn(count)}`,
      busy: "Other items are being cleaned up; wait until that is done",
      nothing: "There is nothing to clean up",
      notChecked: "No inspection result yet",
      /** Why a leftover is only reported. */
      foreign: "In use by another process: only reported, never cleaned up",
      unproven: "Cannot be proven to belong to this VPN Manager or to be stale: only reported, never cleaned up",
      menu: "Recovery actions",
    },
    kind: {
      orphan_worker: "Leftover worker process",
      orphan_sandbox: "Leftover strict isolation sandbox",
      stale_worker_record: "Stale worker record",
      stale_key_lock: "Unused key lock file",
      foreign_key_lock: "Key lock held by another process",
      stale_socket: "Leftover socket",
      foreign_socket: "Socket used by another process",
      temp_file: "Interrupted temporary file",
      app_leftover: "Managed app process not confirmed to have ended",
    },
    outcome: { done: "Done", skipped: "Skipped", failed: "Failed" },
    /** The view's conclusion, worst first. */
    verdict: {
      label: "Recovery verdict",
      cleanable: (count: number) =>
        count === 1 ? "1 leftover item can be cleaned up" : `${count} leftover items can be cleaned up`,
      cleanableDetail: "After you confirm, only the listed items are cleaned up; no connection is started.",
      gaps: (count: number) => (count === 1 ? "1 place could not be checked" : `${count} places could not be checked`),
      gapsDetail:
        "Where the inspection could look, there is nothing to clean up; what is in the places it could not check is unknown.",
      reportOnly: (count: number) => (count === 1 ? "1 item is only reported" : `${count} items are only reported`),
      reportOnlyDetail:
        "They are in use by another process, or cannot be proven to belong to this VPN Manager, so they are not cleaned up.",
      none: "No leftover resources",
      noneDetail: "No leftover processes, sandboxes, records, lock files, sockets or temporary files.",
      /** `when`: relative ("12 seconds ago"). */
      checked: (when: string) => `Checked ${when}`,
      scope: "Handles only what can be proven to belong to this VPN Manager and to be stale",
    },
    cleanable: "Cleanable",
    reportOnly: "Report only",
    item: {
      /** What a leftover belongs to: `name` is an element (a link while it still exists). */
      owner: (app: boolean, name: ReactNode): ReactNode => (
        <>
          {app ? "Managed app " : "Connection "}
          {name}
        </>
      ),
      /** A leftover's name in its controls: its title, and its file when two could share a title. */
      name: (title: string, file: string) => `${title} (${file})`,
      /** What the copy button next to its path copies. */
      path: "path",
      onClean: (action: string) => `When cleaned up: ${action}`,
      /** After an item's name: what cleaning does or did to it (the service's words). */
      then: (text: string) => `: ${text}`,
    },
    result: {
      title: "Cleanup result",
      /** `time`: when the cleanup ended; `operation`: its operation ID, shortened. */
      meta: (time: string, operation: string) => `${time}; operation ${operation}`,
      repeated: "This request was already handled earlier; below is the current state.",
    },
    toast: {
      partial: "Some items were not cleaned up",
      partialDetail: (done: number, failed: number) =>
        `${done} done, ${failed} failed; the results are listed on the page.`,
      cleaned: (count: number) => `Cleaned up ${itemsEn(count)}`,
      /** What a failed cleanup is reported as (the notification adds that it failed). */
      intent: "Clean up leftover resources",
    },
    view: {
      failed: "Cannot check for leftover resources",
      checking: "Checking for leftover resources",
      /** The inspection could not be refreshed: `time` is when the result shown was found. */
      stale: (time: string) => `Cannot update: showing the inspection result from ${time}`,
      gaps: (count: number) =>
        `${count === 1 ? "1 place" : `${count} places`} could not be checked: the results below are incomplete`,
    },
    items: {
      title: "Leftover items",
      description:
        "A process is ended only when its pid, start time and program all match the record; locks or sockets held by another process are only reported and left alone.",
      noneFound:
        "No leftover items were found where the inspection could look; the places listed above could not be checked, so whether anything is left there is unknown.",
      emptyBody:
        "No leftover workers, managed app processes or sandboxes, stale records, unused lock files, sockets nobody answers on, or interrupted temporary files.",
    },
    owned: {
      description: "What the manager holds now; none of it is cleaned up.",
      /** A worker: `name` (its connection) is an element. */
      worker: (pid: number, name: ReactNode, generation: number): ReactNode => (
        <>
          pid {pid} · {name}, generation {generation}
        </>
      ),
      /** A Gateway's connection and whether it serves. */
      listener: (name: string, serving: boolean) => `${name}, ${serving ? "serving" : "refusing connections"}`,
      keyLocks: (total: number, inUse: number) => `${total} total; ${inUse} in use`,
      connectors: (total: number, live: number) => `${total} total; ${live} running`,
    },
    confirm: {
      all: (count: number) => `Clean up ${itemsEn(count)}?`,
      one: (title: string) => `Clean up “${title}”?`,
      scope:
        "Only the items listed below are handled; before cleaning up, each one is checked again to still exist and still belong to this VPN Manager.",
      effect:
        "No connection is started, and nothing the manager owns is touched; deleted files and ended processes cannot be restored.",
    },
  },
  "zh-TW": {
    actions: {
      recheck: "重新檢查",
      clean: "清理",
      cleaning: "清理中",
      cleanCount: (count) => `清理 ${count} 個項目`,
      busy: "正在清理其他項目，完成後再操作",
      nothing: "沒有可以清理的項目",
      notChecked: "還沒有檢查結果",
      foreign: "被其他程序使用：只回報，不會清理",
      unproven: "無法證明屬於這個 VPN Manager 或已經失效：只回報，不會清理",
      menu: "恢復的操作",
    },
    kind: {
      orphan_worker: "遺留的 worker 程序",
      orphan_sandbox: "遺留的嚴格隔離 sandbox",
      stale_worker_record: "過期的 worker 紀錄",
      stale_key_lock: "不再使用的金鑰鎖檔",
      foreign_key_lock: "被其他程序持有的金鑰鎖",
      stale_socket: "遺留的 socket",
      foreign_socket: "被其他程序使用的 socket",
      temp_file: "中斷的暫存檔",
      app_leftover: "無法確認已結束的受管 App 程序",
    },
    outcome: { done: "完成", skipped: "略過", failed: "失敗" },
    verdict: {
      label: "恢復結論",
      cleanable: (count) => `${count} 個遺留項目可以清理`,
      cleanableDetail: "確認後只清理列出的項目；不會啟動任何連線。",
      gaps: (count) => `有 ${count} 處無法檢查`,
      gapsDetail: "在檢查得到的地方沒有可以清理的項目；無法檢查的地方是未知的。",
      reportOnly: (count) => `${count} 個項目只回報`,
      reportOnlyDetail: "它們被其他程序使用，或無法證明屬於這個 VPN Manager，所以不會被清理。",
      none: "沒有遺留的資源",
      noneDetail: "沒有遺留的程序、sandbox、紀錄、鎖檔、socket 或暫存檔。",
      checked: (when) => `${when}檢查`,
      scope: "只處理能證明屬於這個 VPN Manager、而且已經失效的東西",
    },
    cleanable: "可清理",
    reportOnly: "只回報",
    item: {
      owner: (app, name) => (
        <>
          {app ? "受管 App " : "連線 "}
          {name}
        </>
      ),
      name: (title, file) => `${title}（${file}）`,
      path: "路徑",
      onClean: (action) => `清理時：${action}`,
      then: (text) => `：${text}`,
    },
    result: {
      title: "清理結果",
      meta: (time, operation) => `${time}；operation ${operation}`,
      repeated: "這個請求先前已處理過；下面是目前的狀態。",
    },
    toast: {
      partial: "部分項目沒有清理成功",
      partialDetail: (done, failed) => `完成 ${done} 項，失敗 ${failed} 項；結果列在頁面上。`,
      cleaned: (count) => `已清理 ${count} 個項目`,
      intent: "清理遺留資源",
    },
    view: {
      failed: "無法檢查遺留資源",
      checking: "正在檢查遺留資源",
      stale: (time) => `無法更新：顯示的是 ${time} 的檢查結果`,
      gaps: (count) => `有 ${count} 處無法檢查：下面的結果不完整`,
    },
    items: {
      title: "遺留項目",
      description: "程序要 pid、啟動時間與程式都和紀錄相符才會被結束；被其他程序持有的鎖或 socket 只回報、不會動。",
      noneFound: "在檢查得到的地方沒有找到遺留項目；上面列出的地方無法檢查，那裡有沒有遺留項目是未知的。",
      emptyBody:
        "沒有遺留的 worker、受管 App 程序或 sandbox、過期的紀錄、不再使用的鎖檔、沒人接聽的 socket 或中斷的暫存檔。",
    },
    owned: {
      description: "manager 目前持有的東西；這些不會被清理。",
      worker: (pid, name, generation) => (
        <>
          pid {pid} · {name} 第 {generation} 代
        </>
      ),
      listener: (name, serving) => `${name}，${serving ? "服務中" : "拒絕連線中"}`,
      keyLocks: (total, inUse) => `${total} 個；使用中 ${inUse}`,
      connectors: (total, live) => `${total} 個；執行中 ${live}`,
    },
    confirm: {
      all: (count) => `清理 ${count} 個項目？`,
      one: (title) => `清理「${title}」？`,
      scope: "只會處理下面列出的項目；清理前會再確認一次每一項仍然存在、仍然屬於這個 VPN Manager。",
      effect: "不會啟動任何連線，也不動 manager 擁有的資源；刪除的檔案與結束的程序無法復原。",
    },
  },
  ja: {
    actions: {
      recheck: "再チェック",
      clean: "クリーンアップ",
      cleaning: "クリーンアップ中",
      cleanCount: (count) => `${count} 件をクリーンアップ`,
      busy: "ほかの項目をクリーンアップ中です。完了してから操作してください",
      nothing: "クリーンアップできる項目はありません",
      notChecked: "まだチェック結果がありません",
      foreign: "別のプロセスが使用中：報告のみで、クリーンアップしません",
      unproven: "この VPN Manager のものか、すでに無効かを証明できません：報告のみで、クリーンアップしません",
      menu: "復旧の操作",
    },
    kind: {
      orphan_worker: "残留した worker プロセス",
      orphan_sandbox: "残留した厳格な分離のサンドボックス",
      stale_worker_record: "古い worker の記録",
      stale_key_lock: "使われなくなった鍵のロックファイル",
      foreign_key_lock: "別のプロセスが保持している鍵のロック",
      stale_socket: "残留したソケット",
      foreign_socket: "別のプロセスが使用しているソケット",
      temp_file: "中断された一時ファイル",
      app_leftover: "終了を確認できない管理対象アプリのプロセス",
    },
    outcome: { done: "完了", skipped: "スキップ", failed: "失敗" },
    verdict: {
      label: "復旧の結論",
      cleanable: (count) => `${count} 件の残留項目をクリーンアップできます`,
      cleanableDetail: "確認後、一覧の項目だけをクリーンアップします。接続を開始することはありません。",
      gaps: (count) => `${count} か所をチェックできませんでした`,
      gapsDetail: "チェックできた場所にはクリーンアップできる項目はありません。チェックできなかった場所は不明です。",
      reportOnly: (count) => `${count} 件は報告のみです`,
      reportOnlyDetail:
        "別のプロセスが使用しているか、この VPN Manager のものだと証明できないため、クリーンアップしません。",
      none: "残留リソースはありません",
      noneDetail: "残留したプロセス、サンドボックス、記録、ロックファイル、ソケット、一時ファイルはありません。",
      checked: (when) => `チェック：${when}`,
      scope: "この VPN Manager のもので、すでに無効だと証明できるものだけを扱います",
    },
    cleanable: "クリーンアップ可能",
    reportOnly: "報告のみ",
    item: {
      owner: (app, name) => (
        <>
          {app ? "管理対象アプリ " : "接続 "}
          {name}
        </>
      ),
      name: (title, file) => `${title}（${file}）`,
      path: "パス",
      onClean: (action) => `クリーンアップ時：${action}`,
      then: (text) => `：${text}`,
    },
    result: {
      title: "クリーンアップの結果",
      meta: (time, operation) => `${time}、operation ${operation}`,
      repeated: "このリクエストは以前に処理済みです。以下は現在の状態です。",
    },
    toast: {
      partial: "一部の項目をクリーンアップできませんでした",
      partialDetail: (done, failed) => `完了 ${done} 件、失敗 ${failed} 件。結果はページに表示されています。`,
      cleaned: (count) => `${count} 件の項目をクリーンアップしました`,
      intent: "残留リソースのクリーンアップ",
    },
    view: {
      failed: "残留リソースをチェックできません",
      checking: "残留リソースをチェックしています",
      stale: (time) => `更新できません：${time} 時点のチェック結果を表示しています`,
      gaps: (count) => `${count} か所をチェックできませんでした：以下の結果は不完全です`,
    },
    items: {
      title: "残留項目",
      description:
        "プロセスは pid、起動時刻、プログラムがすべて記録と一致した場合にのみ終了します。別のプロセスが保持しているロックやソケットは報告のみで、触れません。",
      noneFound:
        "チェックできた場所には残留項目は見つかりませんでした。上に挙げた場所はチェックできなかったため、残留項目があるかどうかは不明です。",
      emptyBody:
        "残留した worker、管理対象アプリのプロセスやサンドボックス、古い記録、使われなくなったロックファイル、誰も応答しないソケット、中断された一時ファイルはありません。",
    },
    owned: {
      description: "manager が現在保持しているもの。これらはクリーンアップされません。",
      worker: (pid, name, generation) => (
        <>
          pid {pid} · {name} 第 {generation} 世代
        </>
      ),
      listener: (name, serving) => `${name}、${serving ? "稼働中" : "接続を拒否中"}`,
      keyLocks: (total, inUse) => `${total} 個、使用中 ${inUse}`,
      connectors: (total, live) => `${total} 個、実行中 ${live}`,
    },
    confirm: {
      all: (count) => `${count} 件の項目をクリーンアップしますか？`,
      one: (title) => `「${title}」をクリーンアップしますか？`,
      scope:
        "以下に挙げた項目だけを処理します。クリーンアップの前に、各項目がまだ存在し、この VPN Manager のものであることをもう一度確認します。",
      effect:
        "接続を開始することはなく、manager が保有するリソースにも触れません。削除したファイルと終了したプロセスは元に戻せません。",
    },
  },
});
