// Text of the auto-ban log (自動封鎖紀錄, `../bans-page.tsx`) and of a ban's actions (`../ban-actions.ts`). A ban's reason
// comes from the service and is shown as it arrives. The words `../model.ts` writes (durations, the sort orders) are
// in `../messages.tsx`.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    description:
      "Sources banned automatically for opening too many new connections through a port forward in a short time.",
    help: "While banned, a source cannot come in again, and connections to it through a Gateway are refused too. An IPv6 source is counted and banned by the /64 it is in. A ban is removed automatically when it expires; unbanning does not lift the rules of IP blocklists or security profiles.",
    helpText:
      "While banned, a source cannot come in again, and connections to it through a Gateway are refused too; unbanning does not lift the rules of IP blocklists or security profiles.",
    loading: "Loading the ban log",
    /** The list could not be refreshed: `time` is when the data on screen was read. */
    stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
    /** The table's region and its tool strip. */
    log: "Ban log",
    /** Read after the number of bans. */
    unit: (count: number): string => (count === 1 ? "ban" : "bans"),
    /** In place of the name of a connection that no longer exists. */
    deletedConnection: "Deleted connection",
    search: { label: "Search the ban log", placeholder: "Source, reason or connection" },
    filter: { label: "Filter by connection", all: "All connections", deleted: "(deleted connection)" },
    empty: {
      connection: "This connection has no banned sources",
      all: "No banned sources",
      body: "A ban is removed automatically when it expires; only bans still in effect are listed here.",
      noMatch: "No bans match",
    },
    table: {
      label: "Banned sources",
      connection: "Connection",
      reason: "Reason and time banned",
      left: "Remaining",
    },
    row: {
      /** `when` is relative ("3 minutes ago"). */
      bannedAt: (when: string) => `Banned ${when}`,
      /** `banned`: when it was banned; `revision`: the policy version that banned it. */
      meta: (banned: ReactNode, revision: ReactNode): ReactNode => (
        <>
          {banned} · policy version {revision}
        </>
      ),
      until: (time: string) => `Until ${time}`,
      lifting: "Unbanning…",
      expired: "Expired",
    },
    /** What auto-ban can see at all, above the table. */
    coverage: {
      none: "No connection runs auto-ban",
      allOff:
        "Every security profile in use turns auto-ban off; connections without a security profile have it on through the default security policy.",
      noConnections:
        "Once connections exist, those without a security profile turn auto-ban on by the default security policy; your own security profiles turn it on by default too.",
      forwardsUnknown: "Cannot tell whether anything is forwarded",
      forwardsOnly: "Auto-ban counts only connections coming in through a port forward.",
      noForwards: (count: number) =>
        count === 1
          ? "1 connection runs auto-ban, but nothing is forwarded"
          : `${count} connections run auto-ban, but nothing is forwarded`,
      /** `link` leads to the port forwards page, named as its section. */
      noForwardsBody: (link: ReactNode): ReactNode => (
        <>
          Auto-ban counts only new connections coming in through a port forward; with nothing coming in, no ban is
          recorded. Add one under {link}.
        </>
      ),
      /** `link` leads to the port forwards page; its text is `forwardsLink(total)`. */
      covered: (count: number, total: number, link: ReactNode, enabled: number): ReactNode => (
        <>
          {count} {count === 1 ? "connection runs" : "connections run"} auto-ban, with {total} {link} ({enabled}{" "}
          enabled).
        </>
      ),
      forwardsLink: (total: number): string => (total === 1 ? "port forward" : "port forwards"),
    },
    unbanConfirm: {
      title: (source: string) => `Unban ${source}?`,
      titleNone: "Unban?",
      /** `connection`: the name of the connection the source came in through. */
      scope: (connection: string) =>
        `This source can come in to “${connection}” through a port forward again, and connections to it through a Gateway are no longer refused.`,
      rest: "The rules of IP blocklists and security profiles still apply; if it exceeds the threshold again, it is banned again. Other bans are not affected.",
    },
    actions: {
      unban: "Unban",
      unbanning: "Unbanning",
      expired: "Expired; it is removed automatically",
      copySource: "Copy source address",
      openConnection: "Go to its connection",
      connectionDeleted: "This connection was deleted",
      copied: (source: string) => `Copied source address ${source}`,
      copyFailed: "Could not copy the source address",
      copyRefused: (source: string) => `The browser refused access to the clipboard; the source is ${source}.`,
      unbanned: (source: string) => `Unbanned ${source}`,
      applied:
        "The running connection confirmed it no longer bans this source; IP blocklists and the security profile still apply.",
      notRunning: "This connection is not running; the ban is not carried into its next start.",
      recordRemoved: (source: string) => `Removed the ban record of ${source}`,
      unconfirmed:
        "The running connection did not confirm in time; the ban certainly no longer applies once the connection is re-established.",
      /** What a failed lift is reported as (the notification adds that it failed). */
      unbanIntent: (source: string) => `Unban ${source}`,
    },
  },
  "zh-TW": {
    description: "短時間內經轉發開啟過多新連線而被自動封鎖的來源。",
    help: "封鎖期間它無法再連入，經代理埠連到它也會被拒絕。IPv6 來源以它所在的 /64 計算與封鎖。封鎖到期後自動移除；解除封鎖不會解除 IP 封鎖清單或安全設定的規則。",
    helpText: "封鎖期間它無法再連入，經代理埠連到它也會被拒絕；解除封鎖不會解除 IP 封鎖清單或安全設定的規則。",
    loading: "載入封鎖紀錄",
    stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
    log: "封鎖紀錄",
    unit: () => "筆封鎖",
    deletedConnection: "已刪除的連線",
    search: { label: "搜尋封鎖紀錄", placeholder: "來源、原因或連線" },
    filter: { label: "依連線篩選", all: "全部連線", deleted: "（已刪除的連線）" },
    empty: {
      connection: "這條連線沒有封鎖中的來源",
      all: "沒有封鎖中的來源",
      body: "封鎖到期後會自動移除；這裡只列出目前仍有效的封鎖。",
      noMatch: "沒有符合條件的封鎖紀錄",
    },
    table: {
      label: "封鎖中的來源",
      connection: "連線",
      reason: "原因與封鎖時間",
      left: "剩餘",
    },
    row: {
      bannedAt: (when) => `${when}封鎖`,
      meta: (banned, revision) => (
        <>
          {banned} · 政策版本 {revision}
        </>
      ),
      until: (time) => `到 ${time}`,
      lifting: "解除中…",
      expired: "已到期",
    },
    coverage: {
      none: "沒有連線執行自動封鎖",
      allOff: "每條連線使用的安全設定都關閉了自動封鎖；沒有指定安全設定的連線會依預設安全政策開啟。",
      noConnections: "建立連線後，沒有指定安全設定的連線會依預設安全政策開啟自動封鎖；自訂的安全設定也預設開啟。",
      forwardsUnknown: "無法確認是否有轉發",
      forwardsOnly: "自動封鎖只計算經轉發連入的連線。",
      noForwards: (count) => `${count} 條連線啟用自動封鎖，但目前沒有任何轉發`,
      noForwardsBody: (link) => <>自動封鎖只計算經轉發連入的新連線；沒有轉入的連線時不會產生封鎖紀錄。到{link}新增。</>,
      covered: (count, total, link, enabled) => (
        <>
          {count} 條連線啟用自動封鎖，共有 {total} 個{link}（{enabled} 個啟用）。
        </>
      ),
      forwardsLink: () => "轉發",
    },
    unbanConfirm: {
      title: (source) => `解除 ${source} 的封鎖？`,
      titleNone: "解除封鎖？",
      scope: (connection) => `這個來源可以再次經轉發連入「${connection}」，經代理埠連到它也不再被拒絕。`,
      rest: "IP 封鎖清單與安全設定的規則仍然適用；如果它再次超過門檻，會被重新封鎖。其他封鎖不受影響。",
    },
    actions: {
      unban: "解除封鎖",
      unbanning: "解除中",
      expired: "已到期，會自動移除",
      copySource: "複製來源位址",
      openConnection: "前往所屬連線",
      connectionDeleted: "這條連線已被刪除",
      copied: (source) => `已複製來源位址 ${source}`,
      copyFailed: "無法複製來源位址",
      copyRefused: (source) => `瀏覽器拒絕存取剪貼簿；來源是 ${source}。`,
      unbanned: (source) => `已解除 ${source} 的封鎖`,
      applied: "執行中的連線已確認不再封鎖這個來源；IP 封鎖清單與安全設定仍然適用。",
      notRunning: "這條連線目前沒有執行；下次啟動時不會再帶入這筆封鎖。",
      recordRemoved: (source) => `已移除 ${source} 的封鎖紀錄`,
      unconfirmed: "執行中的連線沒有及時確認；它在連線重新建立後一定不再生效。",
      unbanIntent: (source) => `解除 ${source} 的封鎖`,
    },
  },
  ja: {
    description: "短時間にポート転送経由で新しい接続を開きすぎたため、自動的にブロックされた送信元。",
    help: "ブロック中はその送信元から再び着信できず、ゲートウェイ経由でその送信元へ接続することも拒否されます。IPv6 の送信元は、それが属する /64 単位でカウントしてブロックします。ブロックは期限が切れると自動的に削除されます。ブロックを解除しても、IP ブロックリストやセキュリティ設定のルールは解除されません。",
    helpText:
      "ブロック中はその送信元から再び着信できず、ゲートウェイ経由でその送信元へ接続することも拒否されます。ブロックを解除しても、IP ブロックリストやセキュリティ設定のルールは解除されません。",
    loading: "ブロック記録を読み込み中",
    stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
    log: "ブロック記録",
    unit: () => "件のブロック",
    deletedConnection: "削除された接続",
    search: { label: "ブロック記録を検索", placeholder: "送信元、理由、接続" },
    filter: { label: "接続で絞り込み", all: "すべての接続", deleted: "（削除された接続）" },
    empty: {
      connection: "この接続でブロック中の送信元はありません",
      all: "ブロック中の送信元はありません",
      body: "ブロックは期限が切れると自動的に削除されます。ここには現在有効なブロックだけが表示されます。",
      noMatch: "条件に一致するブロック記録はありません",
    },
    table: {
      label: "ブロック中の送信元",
      connection: "接続",
      reason: "理由とブロック日時",
      left: "残り",
    },
    row: {
      bannedAt: (when) => `${when}にブロック`,
      meta: (banned, revision) => (
        <>
          {banned} · ポリシーのバージョン {revision}
        </>
      ),
      until: (time) => `${time} まで`,
      lifting: "解除中…",
      expired: "期限切れ",
    },
    coverage: {
      none: "自動ブロックを実行している接続はありません",
      allOff:
        "すべての接続のセキュリティ設定で自動ブロックがオフになっています。セキュリティ設定を指定していない接続では、既定のセキュリティポリシーによりオンになります。",
      noConnections:
        "接続を作成すると、セキュリティ設定を指定していない接続では既定のセキュリティポリシーにより自動ブロックがオンになります。独自のセキュリティ設定でも既定でオンです。",
      forwardsUnknown: "ポート転送があるか確認できません",
      forwardsOnly: "自動ブロックはポート転送経由で着信した接続だけを数えます。",
      noForwards: (count) => `${count} 件の接続で自動ブロックが有効ですが、ポート転送はありません`,
      noForwardsBody: (link) => (
        <>
          自動ブロックはポート転送経由で着信した新しい接続だけを数えます。転送されてくる接続がなければ、ブロック記録は作られません。
          {link}で追加してください。
        </>
      ),
      covered: (count, total, link, enabled) => (
        <>
          {count} 件の接続で自動ブロックが有効で、{link}は計 {total} 件です（有効 {enabled} 件）。
        </>
      ),
      forwardsLink: () => "ポート転送",
    },
    unbanConfirm: {
      title: (source) => `${source} のブロックを解除しますか？`,
      titleNone: "ブロックを解除しますか？",
      scope: (connection) =>
        `この送信元は再びポート転送経由で「${connection}」に着信できるようになり、ゲートウェイ経由でこの送信元へ接続しても拒否されなくなります。`,
      rest: "IP ブロックリストとセキュリティ設定のルールは引き続き適用されます。再びしきい値を超えると、もう一度ブロックされます。ほかのブロックには影響しません。",
    },
    actions: {
      unban: "ブロック解除",
      unbanning: "解除中",
      expired: "期限切れです。自動的に削除されます",
      copySource: "送信元アドレスをコピー",
      openConnection: "該当する接続へ移動",
      connectionDeleted: "この接続は削除されました",
      copied: (source) => `送信元アドレス ${source} をコピーしました`,
      copyFailed: "送信元アドレスをコピーできませんでした",
      copyRefused: (source) => `ブラウザーがクリップボードへのアクセスを拒否しました。送信元は ${source} です。`,
      unbanned: (source) => `${source} のブロックを解除しました`,
      applied:
        "実行中の接続が、この送信元をブロックしなくなったことを確認しました。IP ブロックリストとセキュリティ設定は引き続き適用されます。",
      notRunning: "この接続は現在実行されていません。次回の起動時にこのブロックは引き継がれません。",
      recordRemoved: (source) => `${source} のブロック記録を削除しました`,
      unconfirmed:
        "実行中の接続から時間内に確認がありませんでした。接続を再確立すれば、このブロックは確実に無効になります。",
      unbanIntent: (source) => `${source} のブロック解除`,
    },
  },
});
