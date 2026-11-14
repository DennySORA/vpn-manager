// Text of the IP blocklists page (IP 封鎖清單, `../blocklists-page.tsx`), its dialogs (`../blocklist-host.tsx`), the list
// actions (`../blocklist-actions.ts`) and the content input and preview (`../blocklist-preview.tsx`). The names,
// descriptions and terms of the built-in lists, a list's refresh message, why it waits for the egress and what a
// preview found wrong come from the service and are shown as they arrive. The words `../model.ts` writes (sizes,
// states, refresh intervals) are in `../messages.tsx`.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** Text from the service (or a shared lower-case word) that starts an English sentence. */
function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const m = defineMessages({
  en: {
    description:
      "Addresses in the lists are refused, both as destinations reached through a Gateway and as sources coming in through a port forward.",
    help: "Lists marked “Built-in” (Spamhaus DROP, DShield) come with the program: they are downloaded and refreshed automatically through the Provider egress connection, apply by default to connections without a security profile, and are selected in new security profiles too. Selecting or clearing a list, updating its content and disabling it all apply to running connections at once, without a restart.",
    helpText:
      "Selecting or clearing a list, updating its content and disabling it all apply to running connections at once, without a restart.",
    add: "Add list",
    newList: "New IP blocklist",
    loading: "Loading blocklists",
    notFound: "This blocklist was not found",
    pick: "Choose a blocklist",
    pickBody:
      "See its source, content statistics, the security profiles that use it and how far connections have applied it.",
    none: "No IP blocklists yet",
    noneBody:
      "Upload, paste or download an IP/CIDR list from a URL, then select it in a security profile: addresses in the list cannot be destinations and cannot come in through a port forward.",
    noneShort: "No blocklists yet",
    noneShortBody: "Add one, then select it in a security profile.",
    /** The list could not be refreshed: `time` is when the data on screen was read. */
    stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
    listLabel: "IP blocklists (by state and name)",
    detailsOf: (name: string) => `Details of ${name}`,
    /** The detail pane while no list is open. */
    details: "Blocklist details",
    all: "All blocklists",
    url: "URL",
    refresh: "Automatic refresh",
    content: "Content",
    downloading: "Downloading",
    previewProblems: "The preview found problems that prevent saving",
    /** A list's state when nothing is wrong with it. */
    enabled: "Enabled",
    notDownloaded: "Not downloaded yet",
    idLabel: "List ID",
    /** Parts of a row's second line. */
    row: {
      byDefault: "Applied by default",
      usedBy: (count: number) => (count === 1 ? "Used by 1 profile" : `Used by ${count} profiles`),
    },
    /** Built-in lists the user deleted, below the list. */
    deleted: {
      heading: "Deleted built-in lists (not added back automatically)",
      restoreOf: (name: string) => `Restore ${name}`,
      restoring: "Restoring",
      busy: "Another list is being restored; wait until it is done",
      restored: (name: string) => `Restored ${name}`,
      restoredNote: "It applies once it is downloaded through the Provider egress connection.",
      /** What a failed restore is reported as (the notification adds that it failed). */
      restoreIntent: (name: string) => `Restore ${name}`,
      restore: "Restore",
    },
    create: {
      previewFirst: "Preview the content first",
      created: (name: string) => `Created ${name}`,
      createdNote: "Once selected in a security profile, it applies at once to the connections that use it.",
      description:
        "Upload, paste or download an IP/CIDR list from a URL; it can be created once the preview confirms how it was parsed.",
      notePreview: "Preview the content first; it can be created once the parsed result is confirmed.",
      noteProblems: "This content cannot be saved: change it and preview again.",
      noteReady: "Preview done; check the content and the name, then create it.",
      namePlaceholder: "For example: Spamhaus DROP",
      previewTitle: "Preview result",
      previewAgain: "Preview again.",
      previewNote:
        "The preview lists the valid entries, the merged ranges, the skipped private addresses and the invalid lines; nothing is saved.",
      format: "List format",
      /** The three nodes are the comment marks `#` and `;` and a JSON line's `{"cidr": …}`, each in code type. */
      formatBody: (hash: ReactNode, semicolon: ReactNode, cidr: ReactNode): ReactNode => (
        <>
          UTF-8 text, one IPv4/IPv6 address or CIDR per line; anything after {hash} or {semicolon} is a comment.
          Spamhaus JSON lines (one {cidr} per line) and DShield's tab-separated start and end addresses are understood
          too. Duplicate, overlapping and adjacent ranges are merged; private and special-use addresses (such as
          10.0.0.0/8, 100.64.0.0/10, loopback) are skipped and counted; anything else, such as host names, URLs or
          address ranges, is an invalid line and has no effect. At most 8 MiB and 200,000 entries; compressed files are
          not imported directly.
        </>
      ),
    },
    /** How one connection stands with this list, from what its worker reported. */
    connections: {
      notRunning: "Not running; applied when it starts",
      applying: (revision: number, applied: number | null) =>
        `Applying (version #${revision}${applied ? `, #${applied} running now` : ""})`,
      applied: (revision: number) => `Applied (version #${revision})`,
      missing: (revision: number) =>
        `The running version #${revision} does not include this list: the connection runs an earlier security profile; it applies after a restart`,
    },
    usage: {
      title: "In use",
      /** `profiles`: how many security profiles keep the disabled list selected. */
      disabled: (profiles: number) =>
        `Disabled: applied to no connection${profiles ? `; ${profiles === 1 ? "1 security profile keeps" : `${profiles} security profiles keep`} it selected, and it applies again as soon as it is enabled` : ""}.`,
      none: "No security profile uses this list; it takes effect once a security profile selects it.",
      defaultPolicy: "Default security policy",
      defaultPolicyNote:
        "Every connection without a security profile applies this built-in list; a connection with a security profile of its own follows that profile's selection.",
      allCustom: "Every connection has a security profile of its own",
      profile: (name: string) => `Security profile “${name}”`,
      profileUnused: "No connection uses this security profile",
    },
    /** The overview of one list. */
    facts: {
      builtin: "Built-in list",
      source: "Source",
      terms: "Terms of use",
      fullTerms: "Full terms",
      downloadUrl: "Download URL",
      uploaded: "Uploaded or pasted text (changes only when the content is updated)",
      nextAt: (time: string) => `Next: ${time}`,
      /** After the refresh interval: when the next refresh is due, relative. */
      relative: (when: string) => ` (${when})`,
      /** After the refresh interval: why the egress cannot download now, from the service. */
      waiting: (reason: string) => ` (waiting for the Provider egress: ${reason})`,
      lastRefresh: "Last refresh",
      succeeded: "Succeeded",
      failed: "Failed",
      neverRefreshed: "Not refreshed yet",
      contentUpdated: "Content updated",
      sha: "Content SHA-256",
    },
    /** Why a list enforces nothing yet: disabled, waiting for the egress, failed, not downloaded yet. */
    state: {
      /** `keeps`: the list holds content downloaded earlier. */
      disabled: (keeps: boolean) =>
        `This list is not downloaded and applies to no connection (the default security policy included)${keeps ? "; the content downloaded last is kept and applies again as soon as the list is enabled" : ""}.`,
      waitingTitle: "Waiting for the Provider egress connection; not downloaded yet",
      /** `reason`: why the egress cannot download now, from the service. */
      waiting: (reason: string) =>
        `${sentence(reason)}. IP blocklists are downloaded only through a VPN connection (never over the first direct connection or the host's own network); once the egress connection can be used, the list is downloaded within a minute. Until then this list blocks no address.`,
      firstFailedTitle: "First download failed",
      firstFailed: (reason: string) =>
        `${sentence(reason)}. It is retried automatically in about an hour, or choose “Refresh now”. Until it is downloaded, this list blocks no address.`,
      awaitingTitle: "Waiting for the first download",
      awaiting:
        "The scheduler downloads it through the Provider egress connection within a minute; until then this list blocks no address.",
    },
    refreshFailed: {
      title: "The latest refresh failed; the content downloaded earlier is still in use",
      /** `when` is relative; `failingSince` and `downloadedAt` are dates, or null when there is nothing to add. */
      body: (reason: string, when: string, failingSince: string | null, downloadedAt: string | null) =>
        `${sentence(reason)} (${when}${failingSince ? `; failing since ${failingSince}` : ""}).${downloadedAt ? ` The current content was downloaded at ${downloadedAt}.` : ""}`,
    },
    /** The footer's line: when the content changes next. */
    next: {
      upload: "Uploaded content changes only with “Update content”.",
      disabled: "Disabled: not refreshed automatically.",
      waiting: (reason: string) => `Waiting for the Provider egress: ${reason}.`,
      at: (when: string, interval: string) => `Next automatic refresh ${when} (${interval}).`,
      interval: (interval: string) => `${interval}.`,
    },
    actions: {
      /** Another action of the list is on its way: `action` is its name. */
      busy: (action: string) => `“${action}” is being sent; wait until it is done`,
      refresh: "Refresh now",
      disabling: "Disabling",
      listDisabled: "This list is disabled",
      replace: "Update content",
      inUse: (count: number) =>
        count === 1
          ? "1 security profile uses this list: clear it there first"
          : `${count} security profiles use this list: clear it in them first`,
      enabled: (name: string) => `Enabled ${name}`,
      disabled: (name: string) => `Disabled ${name}`,
      enabledNote: "Running connections that use it apply it at once.",
      disabledNote: "Running connections stop applying this list at once.",
      /** What a failed action is reported as (the notification adds that it failed). */
      enableIntent: (name: string) => `Enable ${name}`,
      disableIntent: (name: string) => `Disable ${name}`,
      refreshed: (name: string) => `Refreshed ${name}`,
      refreshIntent: (name: string) => `Refresh ${name}`,
      deleted: (name: string) => `Deleted ${name}`,
      builtinDeleted:
        "A built-in list is not added back automatically; restore it under “Deleted built-in lists” at the bottom of the list.",
      deleteIntent: (name: string) => `Delete ${name}`,
    },
    edit: {
      noChanges: "No changes",
      previewFirst: "Download and preview the content of the new URL first",
      saved: (name: string) => `Saved ${name}`,
      title: (name: string) => `Edit ${name}`,
      urlDescription:
        "Name, download URL and automatic refresh; a new URL is downloaded and previewed first, and saved only once its content is confirmed.",
      uploadDescription: "The list's name; replace its content with “Update content”.",
      builtinUrlHint:
        "A built-in list's source is fixed; for another source, add a list. Downloaded through the Provider egress connection.",
      changedUrlHint: "Before changing the URL, download and preview the content of the new one.",
      urlHint: "Downloaded through the Provider egress connection.",
      previewUrl: "Download and preview the new URL",
      newUrlContent: "Content of the new URL",
    },
    replace: {
      previewFirst: "Preview the new content first",
      sameReason: "The content is the same as now; no update is needed",
      done: (name: string) => `Updated the content of ${name}`,
      /** `size`: the new content's size. */
      doneNote: (size: string) => `${size}; running connections that use it apply it at once.`,
      title: (name: string) => `Update the content of ${name}`,
      description:
        "Upload or paste a new list; once the preview is confirmed it replaces the current content, and running connections that use it apply it at once.",
      updating: "Updating",
      confirm: "Replace with the previewed content",
      newContent: "New content",
      same: "The content is the same as now",
      sameBody: "No update is needed.",
    },
    deleteConfirm: {
      title: (name: string) => `Delete the IP blocklist “${name}”?`,
      builtin:
        "This is a built-in list: once deleted it no longer applies to the default security policy and later starts do not add it back (it can be restored under “Deleted built-in lists”). To stop using it for a while, disable it instead.",
      own: "This list and its content are deleted; this cannot be undone. No security profile uses it.",
    },
    /** Where new content comes from, and why it cannot be previewed yet. */
    draft: {
      chooseFile: "Choose a file",
      fileTooLarge: (mib: number) => `The file exceeds the ${mib} MiB limit`,
      pasteList: "Paste the list's content",
      textTooLarge: (mib: number) => `The content exceeds the ${mib} MiB limit`,
      enterUrl: "Enter a URL",
      httpsOnly: "Only https:// URLs are accepted",
      mode: { upload: "Upload a file", paste: "Paste text", url: "URL" },
      source: "Content source",
      fileLabel: "Choose a list file",
      savingFile: "Saving; change the file once it is done",
      changeFile: "Choose another file",
      pickFile: "Choose file",
      fileHint: "Plain text, at most 8 MiB; extract a compressed file first",
      contentLabel: "List content",
      contentHint: "One IPv4/IPv6 address or CIDR per line; anything after # or ; is a comment.",
      placeholder: "# For example\n203.0.113.0/24\n2001:db8:dead::/48  # comment\n198.51.100.7",
      urlHint: "https:// only; downloaded through the Provider egress connection, never directly.",
      savingPreview: "Saving; preview once it is done",
      parsing: "Parsing",
      downloadAndPreview: "Download and preview",
      preview: "Preview",
    },
    /** What parsing found. */
    stats: {
      entries: "Valid entries",
      entriesHint: "Lines holding an address or CIDR",
      special: "Skipped private/special addresses",
      specialHint:
        "Entries covering private, CGNAT, loopback, documentation or other such addresses, in whole or in part",
      invalid: "Invalid lines",
      ranges: (family: string) => `${family} ranges`,
      rangesHint: "After merging duplicate, overlapping and adjacent entries",
      comments: "Comments / blank lines",
      addresses: (family: string) => `${family} addresses`,
      size: "Size",
      sizeHint: "Raw text → merged ranges",
    },
    /** Why private and special-use entries are not blocked; `text` is `count` formatted. */
    special: (text: string, count: number) =>
      `${text} ${count === 1 ? "entry covers" : "entries cover"} private, CGNAT, loopback, multicast, documentation or other special-use addresses, in whole or in part; these addresses are skipped and never blocked: private networks are managed by the security profile's “Private networks allowed through the tunnel”, which is also why the VPN provider's DNS inside the tunnel (for example 10.64.0.1) is not blocked.`,
    invalid: {
      /** `total` is formatted. */
      first: (shown: number, total: string) =>
        `Invalid lines (the first ${shown} of ${total} are listed; these lines have no effect)`,
      all: (total: number) => `Invalid lines (${total} in all; these lines have no effect)`,
      line: "Line",
      content: "Content",
      reason: "Reason",
      blank: "(blank)",
    },
    preview: {
      label: "Preview",
      changed: "The content changed",
      changedBody: "This previews the earlier content; preview again before saving.",
      cannotSave: "Cannot be saved",
      /** `via`: the connection that downloaded it; `url`: what it downloaded; `size`: how much. */
      fetched: (
        via: ReactNode,
        generation: number,
        url: ReactNode,
        size: string,
        contentType: string | null,
      ): ReactNode => (
        <>
          Downloaded {url} through connection {via} (generation {generation}) · {size}
          {contentType ? ` · ${contentType}` : ""}
        </>
      ),
      /** `text` is `count` formatted. */
      hostBits: (text: string, count: number) =>
        count === 1
          ? "1 CIDR had host bits set and was changed to its network."
          : `${text} CIDRs had host bits set and were changed to their networks.`,
      mapped: (text: string, count: number) =>
        count === 1
          ? "1 IPv4-mapped IPv6 address is handled as IPv4."
          : `${text} IPv4-mapped IPv6 addresses are handled as IPv4.`,
      /** The notes above as one paragraph (an empty part is left out). */
      sentences: (parts: readonly string[]) => parts.filter(Boolean).join(" "),
      /** `total` is formatted. */
      sampleFirst: (shown: number, total: string) => `The first ${shown} merged ranges (of ${total})`,
      sampleAll: (count: number) => (count === 1 ? "The 1 merged range" : `The ${count} merged ranges`),
    },
  },
  "zh-TW": {
    description: "清單內的位址：經代理埠連出的目的地與經轉發連入的來源都會被拒絕。",
    help: "標示「內建」的清單（Spamhaus DROP、DShield）由程式內建，經 Provider 出口連線自動下載與更新，預設套用到沒有指定安全設定的連線，新的安全設定也會預先選取。選取或取消清單、更新內容與停用都會立即套用到執行中的連線，不需要重新啟動。",
    helpText: "選取或取消清單、更新內容與停用都會立即套用到執行中的連線，不需要重新啟動。",
    add: "新增清單",
    newList: "新的 IP 封鎖清單",
    loading: "載入封鎖清單",
    notFound: "找不到這份封鎖清單",
    pick: "選擇一份封鎖清單",
    pickBody: "查看它的來源、內容統計、使用它的安全設定與連線的套用狀態。",
    none: "還沒有 IP 封鎖清單",
    noneBody:
      "上傳、貼上或從網址下載一份 IP／CIDR 清單，再於安全設定中選取：清單內的位址不能作為目的地，也不能經 port forward 連入。",
    noneShort: "還沒有封鎖清單",
    noneShortBody: "新增一份後，在安全設定中選取。",
    stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
    listLabel: "IP 封鎖清單（依狀態與名稱）",
    detailsOf: (name) => `${name} 的詳細資料`,
    details: "封鎖清單詳細資料",
    all: "所有封鎖清單",
    url: "網址",
    refresh: "自動更新",
    content: "內容",
    downloading: "下載中",
    previewProblems: "預覽發現無法儲存的問題",
    enabled: "已啟用",
    notDownloaded: "尚未下載",
    idLabel: "清單 ID",
    row: {
      byDefault: "預設套用",
      usedBy: (count) => `${count} 份設定使用`,
    },
    deleted: {
      heading: "已刪除的內建清單（不會自動加回）",
      restoreOf: (name) => `還原 ${name}`,
      restoring: "還原中",
      busy: "正在還原另一份清單，完成後再操作",
      restored: (name) => `已還原 ${name}`,
      restoredNote: "經 Provider 出口連線下載後開始套用。",
      restoreIntent: (name) => `還原 ${name}`,
      restore: "還原",
    },
    create: {
      previewFirst: "請先預覽內容",
      created: (name) => `已建立 ${name}`,
      createdNote: "在安全設定中選取後，會立即套用到使用它的連線。",
      description: "上傳、貼上或從網址下載一份 IP／CIDR 清單；預覽確認解析結果後才能建立。",
      notePreview: "先預覽內容，確認解析結果後才能建立。",
      noteProblems: "這份內容無法儲存：修改後重新預覽。",
      noteReady: "預覽完成；確認內容與名稱後建立。",
      namePlaceholder: "例如：Spamhaus DROP",
      previewTitle: "預覽結果",
      previewAgain: "請重新預覽。",
      previewNote: "預覽會列出有效項目、合併後的範圍、略過的私有位址與無效行；不會儲存任何東西。",
      format: "清單格式",
      formatBody: (hash, semicolon, cidr) => (
        <>
          UTF-8 文字，每行一個 IPv4／IPv6 位址或 CIDR；{hash} 或 {semicolon} 之後是註解。也讀得懂 Spamhaus 的 JSON
          lines（每行一個 {cidr}）與 DShield 以 Tab
          分隔的起訖位址。重複、重疊與相鄰的範圍會合併；私網與特殊用途位址（例如
          10.0.0.0/8、100.64.0.0/10、loopback）會略過並計數；主機名稱、網址、位址範圍等其他內容列為無效行，不會生效。最多
          8 MiB、200,000 筆；壓縮檔不直接匯入。
        </>
      ),
    },
    connections: {
      notRunning: "沒有執行；啟動時套用",
      applying: (revision, applied) => `套用中（版本 #${revision}${applied ? `，目前執行 #${applied}` : ""}）`,
      applied: (revision) => `已套用（版本 #${revision}）`,
      missing: (revision) => `執行中的版本 #${revision} 不含這份清單：連線執行的是先前的安全設定，重新啟動後套用`,
    },
    usage: {
      title: "使用中",
      disabled: (profiles) =>
        `已停用：不套用到任何連線${profiles ? `；${profiles} 份安全設定仍保留選取，啟用後立即恢復` : ""}。`,
      none: "沒有安全設定使用這份清單；在安全設定中選取後才會生效。",
      defaultPolicy: "預設安全政策",
      defaultPolicyNote: "沒有指定安全設定的連線都套用這份內建清單；有自訂安全設定的連線依該設定的選取。",
      allCustom: "目前每條連線都有自訂的安全設定",
      profile: (name) => `安全設定「${name}」`,
      profileUnused: "沒有連線使用這份安全設定",
    },
    facts: {
      builtin: "內建清單",
      source: "來源",
      terms: "使用條款",
      fullTerms: "條款全文",
      downloadUrl: "下載網址",
      uploaded: "上傳或貼上的文字（只有更新內容時才會改變）",
      nextAt: (time) => `下次：${time}`,
      relative: (when) => `（${when}）`,
      waiting: (reason) => `（等待 Provider 出口：${reason}）`,
      lastRefresh: "最近更新",
      succeeded: "成功",
      failed: "失敗",
      neverRefreshed: "尚未更新",
      contentUpdated: "內容更新於",
      sha: "內容 SHA-256",
    },
    state: {
      disabled: (keeps) =>
        `這份清單不會下載，也不套用到任何連線（包括預設安全政策）${keeps ? "；保留最後下載的內容，啟用後立即恢復" : ""}。`,
      waitingTitle: "等待 Provider 出口連線，尚未下載",
      waiting: (reason) =>
        `${reason}。IP 封鎖清單只經 VPN 連線下載（不用首次直連，也不經本機網路）；出口連線可以使用後，會在一分鐘內自動下載。下載前這份清單不封鎖任何位址。`,
      firstFailedTitle: "第一次下載失敗",
      firstFailed: (reason) => `${reason}。約一小時後自動重試，也可以按「立即更新」。下載前這份清單不封鎖任何位址。`,
      awaitingTitle: "等待第一次下載",
      awaiting: "排程會在一分鐘內經 Provider 出口連線下載；下載前這份清單不封鎖任何位址。",
    },
    refreshFailed: {
      title: "最近一次更新失敗，仍使用先前下載的內容",
      body: (reason, when, failingSince, downloadedAt) =>
        `${reason}（${when}${failingSince ? `；自 ${failingSince} 起失敗` : ""}）。${downloadedAt ? `目前的內容在 ${downloadedAt} 下載。` : ""}`,
    },
    next: {
      upload: "上傳的內容只在「更新內容」時改變。",
      disabled: "已停用：不會自動更新。",
      waiting: (reason) => `等待 Provider 出口：${reason}。`,
      at: (when, interval) => `下次自動更新 ${when}（${interval}）。`,
      interval: (interval) => `${interval}。`,
    },
    actions: {
      busy: (action) => `正在送出「${action}」，完成後再操作`,
      refresh: "立即更新",
      disabling: "停用中",
      listDisabled: "這份清單已停用",
      replace: "更新內容",
      inUse: (count) => `${count} 份安全設定使用這份清單：先在安全設定中取消選取`,
      enabled: (name) => `已啟用 ${name}`,
      disabled: (name) => `已停用 ${name}`,
      enabledNote: "使用它的執行中連線會立即套用。",
      disabledNote: "執行中的連線會立即停止套用這份清單。",
      enableIntent: (name) => `啟用 ${name}`,
      disableIntent: (name) => `停用 ${name}`,
      refreshed: (name) => `已更新 ${name}`,
      refreshIntent: (name) => `更新 ${name}`,
      deleted: (name) => `已刪除 ${name}`,
      builtinDeleted: "內建清單不會再自動加回；可以在清單底部的「已刪除的內建清單」還原。",
      deleteIntent: (name) => `刪除 ${name}`,
    },
    edit: {
      noChanges: "沒有變更",
      previewFirst: "請先下載並預覽新網址的內容",
      saved: (name) => `已儲存 ${name}`,
      title: (name) => `編輯 ${name}`,
      urlDescription: "名稱、下載網址與自動更新；新的網址先下載並預覽，確認內容後才儲存。",
      uploadDescription: "清單的名稱；內容請用「更新內容」取代。",
      builtinUrlHint: "內建清單的來源固定；需要其他來源請新增一份清單。經 Provider 出口連線下載。",
      changedUrlHint: "更換網址前請先下載並預覽新網址的內容。",
      urlHint: "經 Provider 出口連線下載。",
      previewUrl: "下載並預覽新網址",
      newUrlContent: "新網址的內容",
    },
    replace: {
      previewFirst: "請先預覽新的內容",
      sameReason: "內容與目前相同，不需要更新",
      done: (name) => `已更新 ${name} 的內容`,
      doneNote: (size) => `${size}；使用它的執行中連線會立即套用。`,
      title: (name) => `更新 ${name} 的內容`,
      description: "上傳或貼上新的清單，預覽確認後取代目前的內容；使用它的執行中連線會立即套用。",
      updating: "更新中",
      confirm: "以預覽的內容取代",
      newContent: "新的內容",
      same: "內容與目前相同",
      sameBody: "不需要更新。",
    },
    deleteConfirm: {
      title: (name) => `刪除 IP 封鎖清單「${name}」？`,
      builtin:
        "這是內建清單：刪除後不再套用到預設安全政策，之後的啟動也不會自動加回（可以在「已刪除的內建清單」還原）。只是暫時不想用的話，請改為停用。",
      own: "這份清單與它的內容會被刪除，無法復原。沒有安全設定使用它。",
    },
    draft: {
      chooseFile: "請選擇檔案",
      fileTooLarge: (mib) => `檔案超過 ${mib} MiB 上限`,
      pasteList: "請貼上清單內容",
      textTooLarge: (mib) => `內容超過 ${mib} MiB 上限`,
      enterUrl: "請輸入網址",
      httpsOnly: "只接受 https:// 網址",
      mode: { upload: "上傳檔案", paste: "貼上文字", url: "網址" },
      source: "內容來源",
      fileLabel: "選擇清單檔案",
      savingFile: "正在儲存，完成後再換檔案",
      changeFile: "換一個檔案",
      pickFile: "選擇檔案",
      fileHint: "純文字檔，最多 8 MiB；壓縮檔請先解壓縮",
      contentLabel: "清單內容",
      contentHint: "每行一個 IPv4／IPv6 位址或 CIDR；# 或 ; 之後是註解。",
      placeholder: "# 例如\n203.0.113.0/24\n2001:db8:dead::/48  # 註解\n198.51.100.7",
      urlHint: "只接受 https://；經 Provider 出口連線下載，不會直接連線。",
      savingPreview: "正在儲存，完成後再預覽",
      parsing: "解析中",
      downloadAndPreview: "下載並預覽",
      preview: "預覽",
    },
    stats: {
      entries: "有效項目",
      entriesHint: "含位址或 CIDR 的行",
      special: "略過的私有／特殊位址",
      specialHint: "整筆或部分是私網、CGNAT、loopback、文件範例等位址的項目",
      invalid: "無效行",
      ranges: (family) => `${family} 範圍`,
      rangesHint: "重複、重疊與相鄰的項目合併後",
      comments: "註解／空行",
      addresses: (family) => `${family} 位址數`,
      size: "大小",
      sizeHint: "原始文字 → 合併後的範圍",
    },
    special: (text) =>
      `${text} 筆項目整筆或部分是私網、CGNAT、loopback、multicast 或文件範例等特殊用途位址，這些位址已略過、不會封鎖：私網由安全設定的「允許經 tunnel 連線的私網」管理，VPN 供應商在 tunnel 內的 DNS（例如 10.64.0.1）也因此不會被擋。`,
    invalid: {
      first: (shown, total) => `無效的行（列出前 ${shown} 行，共 ${total} 行；這些行不會生效）`,
      all: (total) => `無效的行（共 ${total} 行；這些行不會生效）`,
      line: "行",
      content: "內容",
      reason: "原因",
      blank: "（空白）",
    },
    preview: {
      label: "預覽",
      changed: "內容已變更",
      changedBody: "這是先前內容的預覽；請重新預覽後再儲存。",
      cannotSave: "無法儲存",
      fetched: (via, generation, url, size, contentType) => (
        <>
          經連線 {via}（第 {generation} 代）下載 {url} · {size}
          {contentType ? ` · ${contentType}` : ""}
        </>
      ),
      hostBits: (text) => `${text} 個 CIDR 含主機位元，已改為所屬網段。`,
      mapped: (text) => `${text} 個 IPv4 對映的 IPv6 位址以 IPv4 處理。`,
      sentences: (parts) => parts.join(""),
      sampleFirst: (shown, total) => `合併後的前 ${shown} 個範圍（共 ${total} 個）`,
      sampleAll: (count) => `合併後的 ${count} 個範圍`,
    },
  },
  ja: {
    description:
      "リスト内のアドレスは、ゲートウェイ経由で接続する宛先としても、ポート転送経由で着信する送信元としても拒否されます。",
    help: "「組み込み」と表示されたリスト（Spamhaus DROP、DShield）はプログラムに組み込まれています。Provider 出口接続経由で自動的にダウンロード・更新され、セキュリティ設定を指定していない接続に既定で適用され、新しいセキュリティ設定でもあらかじめ選択されます。リストの選択・解除、内容の更新、無効化は、実行中の接続に再起動なしですぐ適用されます。",
    helpText: "リストの選択・解除、内容の更新、無効化は、実行中の接続に再起動なしですぐ適用されます。",
    add: "リストを追加",
    newList: "新しい IP ブロックリスト",
    loading: "ブロックリストを読み込み中",
    notFound: "このブロックリストが見つかりません",
    pick: "ブロックリストを選択",
    pickBody: "取得元、内容の統計、使用しているセキュリティ設定、接続での適用状況を確認できます。",
    none: "IP ブロックリストはまだありません",
    noneBody:
      "IP／CIDR リストをアップロード、貼り付け、または URL からダウンロードし、セキュリティ設定で選択してください。リスト内のアドレスは宛先にできず、ポート転送経由で着信することもできません。",
    noneShort: "ブロックリストはまだありません",
    noneShortBody: "追加したら、セキュリティ設定で選択してください。",
    stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
    listLabel: "IP ブロックリスト（状態と名前の順）",
    detailsOf: (name) => `${name} の詳細`,
    details: "ブロックリストの詳細",
    all: "すべてのブロックリスト",
    url: "URL",
    refresh: "自動更新",
    content: "内容",
    downloading: "ダウンロード中",
    previewProblems: "プレビューで保存できない問題が見つかりました",
    enabled: "有効",
    notDownloaded: "未ダウンロード",
    idLabel: "リスト ID",
    row: {
      byDefault: "既定で適用",
      usedBy: (count) => `${count} 件の設定で使用`,
    },
    deleted: {
      heading: "削除した組み込みリスト（自動では再追加されません）",
      restoreOf: (name) => `${name} を復元`,
      restoring: "復元中",
      busy: "別のリストを復元中です。完了してから操作してください",
      restored: (name) => `${name} を復元しました`,
      restoredNote: "Provider 出口接続経由でダウンロードされると適用が始まります。",
      restoreIntent: (name) => `${name} の復元`,
      restore: "復元",
    },
    create: {
      previewFirst: "先に内容をプレビューしてください",
      created: (name) => `${name} を作成しました`,
      createdNote: "セキュリティ設定で選択すると、それを使用する接続にすぐ適用されます。",
      description:
        "IP／CIDR リストをアップロード、貼り付け、または URL からダウンロードします。プレビューで解析結果を確認してから作成できます。",
      notePreview: "先に内容をプレビューし、解析結果を確認してから作成できます。",
      noteProblems: "この内容は保存できません。修正してからもう一度プレビューしてください。",
      noteReady: "プレビューが完了しました。内容と名前を確認してから作成してください。",
      namePlaceholder: "例：Spamhaus DROP",
      previewTitle: "プレビュー結果",
      previewAgain: "もう一度プレビューしてください。",
      previewNote:
        "プレビューには有効な項目、統合後の範囲、スキップしたプライベートアドレス、無効な行が表示されます。何も保存されません。",
      format: "リストの形式",
      formatBody: (hash, semicolon, cidr) => (
        <>
          UTF-8 テキストで、1 行に 1 つの IPv4／IPv6 アドレスまたは CIDR を書きます。{hash} または {semicolon}{" "}
          以降はコメントです。Spamhaus の JSON lines（1 行に 1 つの {cidr}）と、DShield
          のタブ区切りの開始・終了アドレスも読み取れます。重複・重なり・隣接する範囲は統合されます。プライベートアドレスと特殊用途アドレス（例：10.0.0.0/8、100.64.0.0/10、loopback）はスキップして件数を数えます。ホスト名、URL、アドレス範囲などその他の内容は無効な行となり、適用されません。最大
          8 MiB、200,000 件。圧縮ファイルは直接インポートできません。
        </>
      ),
    },
    connections: {
      notRunning: "未実行。起動時に適用されます",
      applying: (revision, applied) =>
        `適用中（バージョン #${revision}${applied ? `、現在の実行は #${applied}` : ""}）`,
      applied: (revision) => `適用済み（バージョン #${revision}）`,
      missing: (revision) =>
        `実行中のバージョン #${revision} にはこのリストが含まれていません。接続は以前のセキュリティ設定で実行されており、再起動後に適用されます`,
    },
    usage: {
      title: "使用中",
      disabled: (profiles) =>
        `無効：どの接続にも適用されません${profiles ? `。${profiles} 件のセキュリティ設定で選択されたままなので、有効にするとすぐに再適用されます` : ""}。`,
      none: "このリストを使用しているセキュリティ設定はありません。セキュリティ設定で選択すると有効になります。",
      defaultPolicy: "既定のセキュリティポリシー",
      defaultPolicyNote:
        "セキュリティ設定を指定していない接続には、すべてこの組み込みリストが適用されます。独自のセキュリティ設定を持つ接続は、その設定の選択に従います。",
      allCustom: "現在、すべての接続に独自のセキュリティ設定があります",
      profile: (name) => `セキュリティ設定「${name}」`,
      profileUnused: "このセキュリティ設定を使用している接続はありません",
    },
    facts: {
      builtin: "組み込みリスト",
      source: "取得元",
      terms: "利用規約",
      fullTerms: "規約の全文",
      downloadUrl: "ダウンロード URL",
      uploaded: "アップロードまたは貼り付けたテキスト（内容を更新したときだけ変わります）",
      nextAt: (time) => `次回：${time}`,
      relative: (when) => `（${when}）`,
      waiting: (reason) => `（Provider 出口を待機中：${reason}）`,
      lastRefresh: "最終更新",
      succeeded: "成功",
      failed: "失敗",
      neverRefreshed: "未更新",
      contentUpdated: "内容の更新日時",
      sha: "内容の SHA-256",
    },
    state: {
      disabled: (keeps) =>
        `このリストはダウンロードされず、どの接続にも適用されません（既定のセキュリティポリシーを含む）${keeps ? "。最後にダウンロードした内容は保持され、有効にするとすぐに再適用されます" : ""}。`,
      waitingTitle: "Provider 出口接続を待機中のため、未ダウンロード",
      waiting: (reason) =>
        `${reason}。IP ブロックリストは VPN 接続経由でのみダウンロードされます（初回の直接接続もホストのネットワークも使いません）。出口接続が使えるようになると、1 分以内に自動でダウンロードされます。ダウンロードされるまで、このリストはどのアドレスもブロックしません。`,
      firstFailedTitle: "初回のダウンロードに失敗しました",
      firstFailed: (reason) =>
        `${reason}。約 1 時間後に自動で再試行します。「今すぐ更新」を押すこともできます。ダウンロードされるまで、このリストはどのアドレスもブロックしません。`,
      awaitingTitle: "初回のダウンロード待ち",
      awaiting:
        "1 分以内にスケジュールに従って Provider 出口接続経由でダウンロードされます。ダウンロードされるまで、このリストはどのアドレスもブロックしません。",
    },
    refreshFailed: {
      title: "直近の更新に失敗しました。以前にダウンロードした内容を引き続き使用しています",
      body: (reason, when, failingSince, downloadedAt) =>
        `${reason}（${when}${failingSince ? `、${failingSince} から失敗中` : ""}）。${downloadedAt ? `現在の内容は ${downloadedAt} にダウンロードしたものです。` : ""}`,
    },
    next: {
      upload: "アップロードした内容は「内容を更新」でのみ変わります。",
      disabled: "無効：自動では更新されません。",
      waiting: (reason) => `Provider 出口を待機中：${reason}。`,
      at: (when, interval) => `次回の自動更新：${when}（${interval}）。`,
      interval: (interval) => `${interval}。`,
    },
    actions: {
      busy: (action) => `「${action}」を送信中です。完了してから操作してください`,
      refresh: "今すぐ更新",
      disabling: "無効化中",
      listDisabled: "このリストは無効です",
      replace: "内容を更新",
      inUse: (count) =>
        `${count} 件のセキュリティ設定がこのリストを使用しています。先にセキュリティ設定で選択を外してください`,
      enabled: (name) => `${name} を有効にしました`,
      disabled: (name) => `${name} を無効にしました`,
      enabledNote: "このリストを使用している実行中の接続にすぐ適用されます。",
      disabledNote: "実行中の接続は、このリストの適用をすぐに停止します。",
      enableIntent: (name) => `${name} の有効化`,
      disableIntent: (name) => `${name} の無効化`,
      refreshed: (name) => `${name} を更新しました`,
      refreshIntent: (name) => `${name} の更新`,
      deleted: (name) => `${name} を削除しました`,
      builtinDeleted:
        "組み込みリストは自動では再追加されません。一覧の下部にある「削除した組み込みリスト」から復元できます。",
      deleteIntent: (name) => `${name} の削除`,
    },
    edit: {
      noChanges: "変更はありません",
      previewFirst: "先に新しい URL の内容をダウンロードしてプレビューしてください",
      saved: (name) => `${name} を保存しました`,
      title: (name) => `${name} を編集`,
      urlDescription:
        "名前、ダウンロード URL、自動更新。新しい URL は先にダウンロードしてプレビューし、内容を確認してから保存します。",
      uploadDescription: "リストの名前。内容は「内容を更新」で置き換えてください。",
      builtinUrlHint:
        "組み込みリストの取得元は固定です。別の取得元が必要なら、リストを追加してください。Provider 出口接続経由でダウンロードします。",
      changedUrlHint: "URL を変更する前に、新しい URL の内容をダウンロードしてプレビューしてください。",
      urlHint: "Provider 出口接続経由でダウンロードします。",
      previewUrl: "新しい URL をダウンロードしてプレビュー",
      newUrlContent: "新しい URL の内容",
    },
    replace: {
      previewFirst: "先に新しい内容をプレビューしてください",
      sameReason: "内容が現在と同じため、更新は不要です",
      done: (name) => `${name} の内容を更新しました`,
      doneNote: (size) => `${size}。このリストを使用している実行中の接続にすぐ適用されます。`,
      title: (name) => `${name} の内容を更新`,
      description:
        "新しいリストをアップロードまたは貼り付け、プレビューで確認してから現在の内容と置き換えます。このリストを使用している実行中の接続にすぐ適用されます。",
      updating: "更新中",
      confirm: "プレビューした内容で置き換え",
      newContent: "新しい内容",
      same: "内容は現在と同じです",
      sameBody: "更新は不要です。",
    },
    deleteConfirm: {
      title: (name) => `IP ブロックリスト「${name}」を削除しますか？`,
      builtin:
        "これは組み込みリストです。削除すると既定のセキュリティポリシーに適用されなくなり、以降の起動時にも自動では再追加されません（「削除した組み込みリスト」から復元できます）。一時的に使わないだけなら、代わりに無効にしてください。",
      own: "このリストとその内容は削除され、元に戻せません。このリストを使用しているセキュリティ設定はありません。",
    },
    draft: {
      chooseFile: "ファイルを選択してください",
      fileTooLarge: (mib) => `ファイルが上限の ${mib} MiB を超えています`,
      pasteList: "リストの内容を貼り付けてください",
      textTooLarge: (mib) => `内容が上限の ${mib} MiB を超えています`,
      enterUrl: "URL を入力してください",
      httpsOnly: "https:// の URL だけを受け付けます",
      mode: { upload: "ファイルをアップロード", paste: "テキストを貼り付け", url: "URL" },
      source: "内容の取得元",
      fileLabel: "リストファイルを選択",
      savingFile: "保存中です。完了してからファイルを変更してください",
      changeFile: "別のファイルを選択",
      pickFile: "ファイルを選択",
      fileHint: "プレーンテキスト、最大 8 MiB。圧縮ファイルは先に展開してください",
      contentLabel: "リストの内容",
      contentHint: "1 行に 1 つの IPv4／IPv6 アドレスまたは CIDR。# または ; 以降はコメントです。",
      placeholder: "# 例\n203.0.113.0/24\n2001:db8:dead::/48  # コメント\n198.51.100.7",
      urlHint: "https:// のみ。Provider 出口接続経由でダウンロードし、直接は接続しません。",
      savingPreview: "保存中です。完了してからプレビューしてください",
      parsing: "解析中",
      downloadAndPreview: "ダウンロードしてプレビュー",
      preview: "プレビュー",
    },
    stats: {
      entries: "有効な項目",
      entriesHint: "アドレスまたは CIDR を含む行",
      special: "スキップしたプライベート／特殊アドレス",
      specialHint: "全体または一部がプライベート、CGNAT、ループバック、ドキュメント用などのアドレスである項目",
      invalid: "無効な行",
      ranges: (family) => `${family} 範囲`,
      rangesHint: "重複・重なり・隣接する項目を統合した後",
      comments: "コメント／空行",
      addresses: (family) => `${family} アドレス数`,
      size: "サイズ",
      sizeHint: "元のテキスト → 統合後の範囲",
    },
    special: (text) =>
      `${text} 件の項目は、全体または一部がプライベート、CGNAT、ループバック、マルチキャスト、ドキュメント用などの特殊用途アドレスのため、スキップしてブロックしません。プライベートネットワークはセキュリティ設定の「トンネル経由の接続を許可するプライベートネットワーク」で管理されるため、トンネル内にある VPN プロバイダーの DNS（例：10.64.0.1）もブロックされません。`,
    invalid: {
      first: (shown, total) => `無効な行（全 ${total} 行のうち最初の ${shown} 行を表示。これらの行は適用されません）`,
      all: (total) => `無効な行（全 ${total} 行。これらの行は適用されません）`,
      line: "行",
      content: "内容",
      reason: "理由",
      blank: "（空白）",
    },
    preview: {
      label: "プレビュー",
      changed: "内容が変更されました",
      changedBody: "これは以前の内容のプレビューです。もう一度プレビューしてから保存してください。",
      cannotSave: "保存できません",
      fetched: (via, generation, url, size, contentType) => (
        <>
          接続 {via}（第 {generation} 世代）経由で {url} をダウンロード · {size}
          {contentType ? ` · ${contentType}` : ""}
        </>
      ),
      hostBits: (text) => `${text} 件の CIDR にホストビットが含まれていたため、所属するネットワークに変更しました。`,
      mapped: (text) => `${text} 件の IPv4 マップド IPv6 アドレスを IPv4 として扱いました。`,
      sentences: (parts) => parts.join(""),
      sampleFirst: (shown, total) => `統合後の最初の ${shown} 範囲（全 ${total} 範囲）`,
      sampleAll: (count) => `統合後の ${count} 範囲`,
    },
  },
});
