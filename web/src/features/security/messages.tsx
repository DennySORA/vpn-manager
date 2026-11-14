// Text of the security profiles page (安全設定): the list, the editor and its three tabs, the profile actions and the
// deletion, and under `model` the words `model.ts` writes for every page of this folder (sizes, list states, refresh
// intervals, durations, the auto-ban fields). The IP blocklists page keeps its text in `blocklists/messages.tsx` and the
// auto-ban log in `bans/messages.tsx`: one table for the whole folder would pass 900 lines.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    description:
      "Which destinations connections may reach and which sources may come in; the policy is enforced inside each connection.",
    help: "The order of the checks (what an earlier check refuses, no later rule can open): system rules (loopback, link-local, multicast, the host itself and the other connections are always refused) → IP versions the connection does not have → private networks need allowing → allowed destinations → allowed ports → blocked ports → IP blocklists and auto-ban. IP blocklists apply to running connections at once; the other rules take effect when the connection restarts. A connection with a security profile applies only the lists and the auto-ban settings that profile selects, not the default security policy; IP blocklists hold no private addresses, so an allowed private network is never blocked by a list.",
    helpText:
      "What an earlier check refuses, no later rule can open; IP blocklists apply at once, the other rules when the connection restarts.",
    add: "Add security profile",
    newProfile: "New security profile",
    loading: "Loading security profiles",
    loadingLists: "Loading IP blocklists",
    notFound: "This security profile was not found",
    pick: "Choose a security profile",
    pickBody:
      "See and edit the private networks and destinations it allows, the ports it blocks, its IP blocklists and auto-ban.",
    none: "No security profiles of your own yet",
    noneBody:
      "Connections without a security profile use the default security policy: only public internet addresses are allowed, every enabled built-in IP blocklist applies, and auto-ban is on. Create a security profile when a connection has to reach an office or lab network through the tunnel, its destinations need limiting, or it should use other IP blocklists.",
    noneShort: "Connections without one use the default security policy.",
    /** The list could not be refreshed: `time` is when the data on screen was read. */
    stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
    listLabel: "List of security profiles",
    /** The detail pane while no profile is open. */
    detail: "Security profile",
    settingsOf: (name: string) => `Settings of ${name}`,
    all: "All security profiles",
    /** How many connections use a profile (a tag beside its name). */
    usedBy: (count: number) =>
      count === 0 ? "No connection uses it" : count === 1 ? "Used by 1 connection" : `Used by ${count} connections`,
    /** A row's second line ends with how many connections use the profile. */
    connections: (count: number) => (count === 1 ? "1 connection" : `${count} connections`),
    /** What a profile holds, one fact per part (a row's second line, the editor's description). */
    summary: {
      allowsPrivate: (count: number) => (count === 1 ? "Allows 1 private network" : `Allows ${count} private networks`),
      publicOnly: "Public addresses only",
      allowRules: "Allow rules",
      blockedPorts: (count: number) => (count === 1 ? "Blocks 1 port" : `Blocks ${count} ports`),
      blocklists: (count: number) => (count === 1 ? "1 blocklist" : `${count} blocklists`),
      autoBan: "Auto-ban",
    },
    /** What a connection's worker enforces of this profile now. */
    connection: {
      notRunning: "Not running",
      applied: (revision: number) => `Blocklist version #${revision} applied`,
      applying: (revision: number) => `Applying blocklist version #${revision}`,
      /** Follows the state above, separator included. */
      othersAfterRestart: " · The other security rules apply after a restart",
    },
    picker: {
      loadFailed: "Could not load the blocklists",
      loading: "Loading blocklists",
      none: "No IP blocklists yet",
      add: "Add list",
      noneBody: "First upload, paste or download a list from a URL under “IP blocklists”.",
      stale: "Refresh failed; using the earlier content",
      awaiting: "Not downloaded yet: it blocks no address until the first download",
      /** Follows the list's size, separator included. */
      disabledNote: "; disabled, so it does not apply even when selected",
      view: "View",
      selected: (count: number, max: number) =>
        `${count} selected (at most ${max}). Addresses in the lists cannot be destinations and cannot come in through a port forward.`,
    },
    tabs: { destinations: "Destinations", blocking: "Blocking" },
    editor: {
      description: "Where connections may go, IP blocklists and auto-ban.",
      idLabel: "Security profile ID",
      appliesWhen: "IP blocklists apply at once; the other rules apply when the connections that use it restart.",
      unused: "No connection uses it yet; select it in a connection's settings.",
      afterCreating: "Once created, it can be selected in a connection's settings.",
      views: (name: string) => `Views of ${name}`,
      newViews: "Views of the new security profile",
      /** Read after the number of problems in a tab. */
      problems: (count: number): string => (count === 1 ? "problem" : "problems"),
      defaultsTitle: "Defaults match the built-in lists",
      defaultsBody:
        "A new security profile starts with every enabled built-in IP blocklist selected and auto-ban on, the same as the default security policy of connections without a security profile; once a list is cleared, the connections using this profile no longer apply it.",
      namePlaceholder: "For example: office network",
      saved: (name: string) => `Saved ${name}`,
      listsSent:
        "The IP blocklists are sent at once to the running connections that use it, without a restart; “Connections using it” shows where they are applied.",
      created: (name: string) => `Created ${name}`,
    },
    users: {
      title: "Connections using it",
      label: "Connections that use this security profile",
      afterRestart: "Applies after a restart",
      none: "No connection uses this profile; it takes effect once a connection's settings select it.",
    },
    allow: {
      title: "Private networks allowed through the tunnel",
      label: "CIDR list",
      hint: "One per line, for example 10.64.0.0/10 or fd00::/8; reachable only within the AllowedIPs of the WireGuard profile.",
    },
    firewall: {
      title: "Firewall allow rules",
      note: "Empty means no restriction; once anything is listed, every other destination or port is refused (default refuse).",
      destinations: "Allowed destinations",
      destinationsHint:
        "One CIDR per line, for example 203.0.113.0/24; 0.0.0.0/0 means all of IPv4 (and refuses all of IPv6).",
      privateWarning: (nets: readonly string[]) =>
        nets.length === 1
          ? `${nets.join(", ")} is a private network: list it under “Private networks allowed through the tunnel” above as well to let it through`
          : `${nets.join(", ")} are private networks: list them under “Private networks allowed through the tunnel” above as well to let them through`,
      destinationsPlaceholder: "Empty: any public address",
      ports: "Allowed destination ports",
      portsHint: "Separated by commas or spaces; ranges are fine, for example 80, 443, 8000-8999.",
      portsPlaceholder: "Empty: any port",
    },
    ports: {
      title: "Blocked destination ports",
      field: "Ports",
      hint: "Separated by commas or spaces; proxied connections to these ports are refused (even within the allowed ranges).",
      allListed: "All of them are listed already",
      presets: { smtp: "Sending mail (SMTP)", windowsSharing: "Windows file sharing", remoteDesktop: "Remote desktop" },
    },
    manageLists: "Manage lists",
    autoBan: {
      title: "Auto-ban",
      log: "Ban log",
      switchLabel: "Ban sources that open too many new connections in a short time",
      switchHint:
        "Only new connections coming in through a port forward count (not failed logins). While banned, the source cannot come in again, and connections to it through a Gateway are refused too; the WireGuard peer and the DNS servers a connection needs are never banned.",
      forwardsUnknown: "Cannot tell whether anything is forwarded",
      unused: "No connection uses this security profile",
      unusedBody: "Auto-ban starts counting once a connection uses it.",
      noForwards: "The connections using this profile have no port forwards",
      /** `link` leads to the port forwards, its text is `createForward`. */
      noForwardsBody: (link: ReactNode): ReactNode => (
        <>Auto-ban only looks at connections coming in through a port forward; until you {link}, it bans no source.</>
      ),
      createForward: "create a port forward",
      forwards: (total: number, enabled: number) =>
        `The connections using this profile have ${total} port ${total === 1 ? "forward" : "forwards"} (${enabled} enabled).`,
      /** A field's label and the unit of its value. */
      field: (label: string, unit: string) => `${label} (${unit})`,
      /** The four numbers as typed, each already formatted. */
      summary: (on: boolean, windowSecs: string, threshold: string, banSecs: string, max: string) =>
        `${on ? "A" : "Once enabled, a"} source that opens more than ${threshold} new connections within ${windowSecs} seconds is banned for ${banSecs} seconds; at most ${max} sources are banned at once. The settings take effect when the connection restarts.`,
    },
    errors: {
      allowFormat: (bad: readonly string[]) =>
        `Not valid: ${bad.join(", ")} (a CIDR is needed, for example 10.64.0.0/10)`,
      allowSpecial: (nets: readonly string[]) =>
        `Loopback, link-local, multicast or the whole address space cannot be allowed: ${nets.join(", ")}`,
      atMostNetworks: (max: number) => `At most ${max} networks`,
      format: (bad: readonly string[]) => `Not valid: ${bad.join(", ")}`,
      destSpecial: (nets: readonly string[]) =>
        `Loopback, link-local or multicast addresses cannot be allowed: ${nets.join(", ")}`,
      portRange: (bad: readonly string[]) =>
        `Not a valid port or range: ${bad.join(", ")} (for example 443 or 8000-8999)`,
      atMostRanges: (max: number) => `At most ${max} ports or ranges`,
      port: (bad: readonly string[]) => `Not a valid port: ${bad.join(", ")}`,
      atMostPorts: (max: number) => `At most ${max} ports`,
      atMostLists: (max: number) => `Select at most ${max} lists`,
      overlayTooLarge: "Together the selected lists exceed the 16 MiB limit; select fewer lists",
    },
    actions: {
      deleting: "“Delete” is being sent; wait until it is done",
      inUse: (count: number) =>
        count === 1
          ? "1 connection uses this profile: switch it to another security profile first"
          : `${count} connections use this profile: switch them to another security profile first`,
      deleted: (name: string) => `Deleted security profile ${name}`,
      /** What a failed deletion is reported as (the notification adds that it failed). */
      deleteIntent: (name: string) => `Delete ${name}`,
    },
    deleteConfirm: {
      title: (name: string) => `Delete the security profile “${name}”?`,
      /** `lists`: how many IP blocklists the profile selects. */
      body: (lists: number) =>
        `Its rules${lists ? ` and its selection of ${lists} IP ${lists === 1 ? "blocklist" : "blocklists"}` : ""} are deleted with it; the lists themselves are not affected. No connection uses this profile, so no connection is affected.`,
    },
    /** The words of `model.ts`, which every page of this folder shows. */
    model: {
      autoBan: {
        window: { label: "Counting window", unit: "seconds" },
        threshold: { label: "Threshold", unit: "new connections" },
        ban: { label: "Ban duration", unit: "seconds" },
        maxBans: { label: "Simultaneous ban limit", unit: "sources" },
        notWhole: (label: string) => `${label} must be a whole number`,
        /** `min` and `max` are formatted. */
        outOfRange: (label: string, min: string, max: string, unit: string) =>
          `${label} must be between ${min} and ${max} ${unit}`,
      },
      /** The name of a profile made to allow these private ranges. */
      allowRangesName: (ranges: readonly string[]) => `Allow ${ranges.join(", ")}`,
      /** A count too large to show exactly: three significant digits. */
      about: (mantissa: string, exponent: number) => `about ${mantissa} × 10^${exponent}`,
      /** `text` is `count` formatted. */
      entries: (text: string, count: number) => `${text} ${count === 1 ? "entry" : "entries"}`,
      /** Merged ranges of one address family; `text` is `count` formatted. */
      ranges: (family: string, text: string, count: number) => `${family} ${text} ${count === 1 ? "range" : "ranges"}`,
      source: { upload: "Uploaded", url: "URL" },
      format: {
        plain: "One address or CIDR per line",
        json_lines: "JSON lines (one cidr per line)",
        tab_ranges: "Tab-separated start and end addresses and mask",
      },
      bothFamilies: "IPv4 + IPv6",
      state: {
        waiting: "Waiting for the Provider egress",
        firstFailed: "First download failed",
        awaiting: "Waiting for download",
        refreshFailed: "Refresh failed",
      },
      refresh: {
        manual: "Manual refresh only",
        daily: "Daily",
        weekly: "Weekly",
        every: (hours: number) => `Every ${hours} hours`,
      },
      duration: {
        days: (days: number, hours: number) => `${days} d ${hours} h`,
        hours: (hours: number, minutes: number) => `${hours} h ${minutes} min`,
        /** `seconds` has two digits. */
        minutes: (minutes: number, seconds: string) => `${minutes} min ${seconds} s`,
        seconds: (seconds: number) => `${seconds} s`,
      },
      banSort: { newest: "Time banned", expiry: "Time left" },
    },
  },
  "zh-TW": {
    description: "連線可以到達哪些目的地、哪些來源可以連入；政策在連線內部執行。",
    help: "檢查順序（前面拒絕的，後面的規則打不開）：系統規則（loopback、link-local、multicast、主機本身與其他連線永遠拒絕）→ 連線沒有的 IP 版本 → 私網需要允許 → 允許的目的地 → 允許的 port → 封鎖的 port → IP 封鎖清單與自動封鎖。IP 封鎖清單立即套用到執行中的連線；其他規則在連線重新啟動後生效。使用安全設定的連線只套用它選取的清單與自動封鎖設定，不再套用預設安全政策；IP 封鎖清單不含私網位址，所以允許的私網不會被清單擋住。",
    helpText: "前面拒絕的，後面的規則打不開；IP 封鎖清單立即套用，其他規則在連線重新啟動後生效。",
    add: "新增安全設定",
    newProfile: "新的安全設定",
    loading: "載入安全設定",
    loadingLists: "載入 IP 封鎖清單",
    notFound: "找不到這份安全設定",
    pick: "選擇一份安全設定",
    pickBody: "查看與編輯它允許的私網與目的地、封鎖的 port、IP 封鎖清單與自動封鎖。",
    none: "還沒有自訂安全設定",
    noneBody:
      "沒有指定安全設定的連線使用預設安全政策：只允許公開網際網路位址，套用所有啟用中的內建 IP 封鎖清單，並開啟自動封鎖。需要經 tunnel 連到公司或實驗室內網、限制可連的目的地，或改用其他 IP 封鎖清單時，再建立安全設定。",
    noneShort: "沒有指定的連線使用預設安全政策。",
    stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
    listLabel: "安全設定清單",
    detail: "安全設定",
    settingsOf: (name) => `${name} 的設定`,
    all: "所有安全設定",
    usedBy: (count) => (count ? `${count} 條連線使用` : "沒有連線使用"),
    connections: (count) => `${count} 條連線`,
    summary: {
      allowsPrivate: (count) => `允許 ${count} 個私網`,
      publicOnly: "只允許公開位址",
      allowRules: "有允許規則",
      blockedPorts: (count) => `封鎖 ${count} 個埠`,
      blocklists: (count) => `${count} 份封鎖清單`,
      autoBan: "自動封鎖",
    },
    connection: {
      notRunning: "沒有執行",
      applied: (revision) => `封鎖清單版本 #${revision} 已套用`,
      applying: (revision) => `封鎖清單版本 #${revision} 套用中`,
      othersAfterRestart: " · 其他安全規則重新啟動後才會套用",
    },
    picker: {
      loadFailed: "無法載入封鎖清單",
      loading: "載入封鎖清單",
      none: "還沒有 IP 封鎖清單",
      add: "新增清單",
      noneBody: "先在「IP 封鎖清單」上傳、貼上或從網址下載一份清單。",
      stale: "更新失敗，使用先前內容",
      awaiting: "尚未下載；下載前不封鎖任何位址",
      disabledNote: "；停用中，選取後也不會套用",
      view: "檢視",
      selected: (count, max) => `已選 ${count} 份（最多 ${max} 份）。清單內的位址不能作為目的地，也不能經轉發連入。`,
    },
    tabs: { destinations: "目的地", blocking: "封鎖" },
    editor: {
      description: "連線可以到達的目的地、IP 封鎖清單與自動封鎖。",
      idLabel: "安全設定 ID",
      appliesWhen: "IP 封鎖清單立即套用；其他規則在使用它的連線重新啟動後套用。",
      unused: "還沒有連線使用；在連線的設定中選用。",
      afterCreating: "建立後可以在連線的設定中選用。",
      views: (name) => `${name} 的檢視`,
      newViews: "新的安全設定的檢視",
      problems: () => "個問題",
      defaultsTitle: "預設與內建清單相同",
      defaultsBody:
        "新的安全設定預先選取所有啟用中的內建 IP 封鎖清單，並開啟自動封鎖，與沒有指定安全設定的連線所用的預設安全政策相同；取消選取後，使用這份設定的連線就不套用該清單。",
      namePlaceholder: "例如：公司內網",
      saved: (name) => `已儲存 ${name}`,
      listsSent: "IP 封鎖清單會立即送到使用它的執行中連線，不需要重新啟動；套用狀態見「使用中的連線」。",
      created: (name) => `已建立 ${name}`,
    },
    users: {
      title: "使用中的連線",
      label: "使用這份安全設定的連線",
      afterRestart: "重新啟動後套用",
      none: "沒有連線使用這份設定；在連線的設定中選用後才會生效。",
    },
    allow: {
      title: "允許經 tunnel 連線的私網",
      label: "CIDR 清單",
      hint: "每行一個，例如 10.64.0.0/10 或 fd00::/8；必須在 WireGuard 設定的 AllowedIPs 範圍內才到得了。",
    },
    firewall: {
      title: "防火牆允許規則",
      note: "留空表示不限制；一旦列出，其他目的地或 port 一律拒絕（預設拒絕）。",
      destinations: "允許的目的地",
      destinationsHint: "每行一個 CIDR，例如 203.0.113.0/24；0.0.0.0/0 表示所有 IPv4（同時拒絕所有 IPv6）。",
      privateWarning: (nets) => `${nets.join("、")} 是私網：還要列在上方「允許經 tunnel 連線的私網」才會放行`,
      destinationsPlaceholder: "留空：任何公開位址",
      ports: "允許的目的 port",
      portsHint: "以逗號或空白分隔，可用範圍，例如 80, 443, 8000-8999。",
      portsPlaceholder: "留空：任何 port",
    },
    ports: {
      title: "封鎖的目的 port",
      field: "port",
      hint: "以逗號或空白分隔；連到這些 port 的代理連線會被拒絕（即使在允許的範圍內）。",
      allListed: "已經全部列出",
      presets: { smtp: "寄信（SMTP）", windowsSharing: "Windows 檔案分享", remoteDesktop: "遠端桌面" },
    },
    manageLists: "管理清單",
    autoBan: {
      title: "自動封鎖",
      log: "封鎖紀錄",
      switchLabel: "封鎖短時間內開啟過多新連線的來源",
      switchHint:
        "只計算經轉發連入的新連線（不是登入失敗次數）。封鎖期間該來源無法再連入，經代理埠連到它也會被拒絕；連線需要的 WireGuard 對端與 DNS 伺服器永遠不會被封鎖。",
      forwardsUnknown: "無法確認是否有轉發",
      unused: "沒有連線使用這份安全設定",
      unusedBody: "連線使用它之後，自動封鎖才會開始計數。",
      noForwards: "使用這份設定的連線目前沒有任何轉發",
      noForwardsBody: (link) => <>自動封鎖只看經轉發連入的連線；在{link}之前，它不會封鎖任何來源。</>,
      createForward: "建立轉發",
      forwards: (total, enabled) => `使用這份設定的連線共有 ${total} 個轉發（${enabled} 個啟用）。`,
      field: (label, unit) => `${label}（${unit}）`,
      summary: (on, windowSecs, threshold, banSecs, max) =>
        `${on ? "" : "啟用後，"}同一來源在 ${windowSecs} 秒內開啟超過 ${threshold} 個新連線，封鎖 ${banSecs} 秒；同時最多封鎖 ${max} 個來源。設定在連線重新啟動後生效。`,
    },
    errors: {
      allowFormat: (bad) => `格式不正確：${bad.join("、")}（需要 CIDR，例如 10.64.0.0/10）`,
      allowSpecial: (nets) => `不可允許 loopback、link-local、multicast 或整個位址空間：${nets.join("、")}`,
      atMostNetworks: (max) => `最多 ${max} 個`,
      format: (bad) => `格式不正確：${bad.join("、")}`,
      destSpecial: (nets) => `不可允許 loopback、link-local 或 multicast 位址：${nets.join("、")}`,
      portRange: (bad) => `無效的 port 或範圍：${bad.join("、")}（例如 443 或 8000-8999）`,
      atMostRanges: (max) => `最多 ${max} 組`,
      port: (bad) => `無效的埠：${bad.join("、")}`,
      atMostPorts: (max) => `最多 ${max} 個`,
      atMostLists: (max) => `最多選 ${max} 份`,
      overlayTooLarge: "選取的清單合併後超過 16 MiB 上限，請減少清單",
    },
    actions: {
      deleting: "正在送出「刪除」，完成後再操作",
      inUse: (count) => `${count} 條連線使用這份設定：先讓它們改用其他安全設定`,
      deleted: (name) => `已刪除安全設定 ${name}`,
      deleteIntent: (name) => `刪除 ${name}`,
    },
    deleteConfirm: {
      title: (name) => `刪除安全設定「${name}」？`,
      body: (lists) =>
        `它的規則${lists ? `與 ${lists} 份 IP 封鎖清單的選取` : ""}會一起刪除；清單本身不受影響。沒有連線使用這份設定，所以不影響任何連線。`,
    },
    model: {
      autoBan: {
        window: { label: "計數視窗", unit: "秒" },
        threshold: { label: "新連線門檻", unit: "個" },
        ban: { label: "封鎖時間", unit: "秒" },
        maxBans: { label: "同時封鎖上限", unit: "個來源" },
        notWhole: (label) => `${label}需要整數`,
        outOfRange: (label, min, max, unit) => `${label}必須介於 ${min} 與 ${max} ${unit}`,
      },
      allowRangesName: (ranges) => `允許 ${ranges.join("、")}`,
      about: (mantissa, exponent) => `約 ${mantissa} × 10^${exponent}`,
      entries: (text) => `${text} 筆`,
      ranges: (family, text) => `${family} ${text} 段`,
      source: { upload: "上傳", url: "網址" },
      format: {
        plain: "每行一個位址或 CIDR",
        json_lines: "JSON lines（每行一個 cidr）",
        tab_ranges: "Tab 分隔的起訖位址與遮罩",
      },
      bothFamilies: "IPv4＋IPv6",
      state: {
        waiting: "等待 Provider 出口",
        firstFailed: "首次下載失敗",
        awaiting: "等待下載",
        refreshFailed: "更新失敗",
      },
      refresh: {
        manual: "只在手動時更新",
        daily: "每天",
        weekly: "每週",
        every: (hours) => `每 ${hours} 小時`,
      },
      duration: {
        days: (days, hours) => `${days} 天 ${hours} 小時`,
        hours: (hours, minutes) => `${hours} 小時 ${minutes} 分`,
        minutes: (minutes, seconds) => `${minutes} 分 ${seconds} 秒`,
        seconds: (seconds) => `${seconds} 秒`,
      },
      banSort: { newest: "封鎖時間", expiry: "剩餘時間" },
    },
  },
  ja: {
    description: "接続がどの宛先に到達でき、どの送信元から着信できるか。ポリシーは接続の内部で実行されます。",
    help: "チェックの順序（前のチェックで拒否されたものは、後のルールでは開けません）：システムルール（ループバック、リンクローカル、マルチキャスト、ホスト自身、ほかの接続は常に拒否）→ 接続にない IP バージョン → プライベートネットワークは許可が必要 → 許可する宛先 → 許可するポート → ブロックするポート → IP ブロックリストと自動ブロック。IP ブロックリストは実行中の接続にすぐ適用され、その他のルールは接続の再起動後に有効になります。セキュリティ設定を使う接続には、その設定で選択したリストと自動ブロックの設定だけが適用され、既定のセキュリティポリシーは適用されません。IP ブロックリストにはプライベートアドレスが含まれないため、許可したプライベートネットワークがリストでブロックされることはありません。",
    helpText:
      "前のチェックで拒否されたものは、後のルールでは開けません。IP ブロックリストはすぐに適用され、その他のルールは接続の再起動後に有効になります。",
    add: "セキュリティ設定を追加",
    newProfile: "新しいセキュリティ設定",
    loading: "セキュリティ設定を読み込み中",
    loadingLists: "IP ブロックリストを読み込み中",
    notFound: "このセキュリティ設定が見つかりません",
    pick: "セキュリティ設定を選択",
    pickBody:
      "許可するプライベートネットワークと宛先、ブロックするポート、IP ブロックリスト、自動ブロックを確認・編集します。",
    none: "独自のセキュリティ設定はまだありません",
    noneBody:
      "セキュリティ設定を指定していない接続は、既定のセキュリティポリシーを使います。公開インターネットアドレスだけを許可し、有効な組み込み IP ブロックリストをすべて適用し、自動ブロックをオンにします。トンネル経由で社内や研究室のネットワークに接続したいとき、接続先を制限したいとき、別の IP ブロックリストを使いたいときに、セキュリティ設定を作成してください。",
    noneShort: "指定のない接続は既定のセキュリティポリシーを使います。",
    stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
    listLabel: "セキュリティ設定の一覧",
    detail: "セキュリティ設定",
    settingsOf: (name) => `${name} の設定`,
    all: "すべてのセキュリティ設定",
    usedBy: (count) => (count ? `${count} 件の接続が使用中` : "使用中の接続なし"),
    connections: (count) => `${count} 件の接続`,
    summary: {
      allowsPrivate: (count) => `プライベートネットワーク ${count} 件を許可`,
      publicOnly: "公開アドレスのみ許可",
      allowRules: "許可ルールあり",
      blockedPorts: (count) => `ポート ${count} 個をブロック`,
      blocklists: (count) => `ブロックリスト ${count} 件`,
      autoBan: "自動ブロック",
    },
    connection: {
      notRunning: "実行していません",
      applied: (revision) => `ブロックリストのバージョン #${revision} を適用済み`,
      applying: (revision) => `ブロックリストのバージョン #${revision} を適用中`,
      othersAfterRestart: " · その他のセキュリティルールは再起動後に適用されます",
    },
    picker: {
      loadFailed: "ブロックリストを読み込めませんでした",
      loading: "ブロックリストを読み込み中",
      none: "IP ブロックリストはまだありません",
      add: "リストを追加",
      noneBody:
        "まず「IP ブロックリスト」で、リストをアップロード、貼り付け、または URL からダウンロードしてください。",
      stale: "更新に失敗、以前の内容を使用中",
      awaiting: "未ダウンロード。ダウンロードするまでアドレスをブロックしません",
      disabledNote: "。無効のため、選択しても適用されません",
      view: "表示",
      selected: (count, max) =>
        `${count} 件を選択中（最大 ${max} 件）。リスト内のアドレスは宛先にできず、ポート転送経由で着信することもできません。`,
    },
    tabs: { destinations: "宛先", blocking: "ブロック" },
    editor: {
      description: "接続が到達できる宛先、IP ブロックリスト、自動ブロック。",
      idLabel: "セキュリティ設定 ID",
      appliesWhen:
        "IP ブロックリストはすぐに適用されます。その他のルールは、使用している接続の再起動後に適用されます。",
      unused: "まだ使用している接続はありません。接続の設定で選んでください。",
      afterCreating: "作成後、接続の設定で選べます。",
      views: (name) => `${name} のビュー`,
      newViews: "新しいセキュリティ設定のビュー",
      problems: () => "件の問題",
      defaultsTitle: "既定は組み込みリストと同じ",
      defaultsBody:
        "新しいセキュリティ設定では、有効な組み込み IP ブロックリストがすべてあらかじめ選択され、自動ブロックもオンになっています。セキュリティ設定を指定していない接続が使う既定のセキュリティポリシーと同じです。選択を外すと、この設定を使う接続にはそのリストが適用されなくなります。",
      namePlaceholder: "例：社内ネットワーク",
      saved: (name) => `${name} を保存しました`,
      listsSent:
        "IP ブロックリストは、この設定を使用している実行中の接続にすぐ送られます。再起動は不要です。適用状況は「使用中の接続」で確認できます。",
      created: (name) => `${name} を作成しました`,
    },
    users: {
      title: "使用中の接続",
      label: "このセキュリティ設定を使用している接続",
      afterRestart: "再起動後に適用",
      none: "この設定を使用している接続はありません。接続の設定で選ぶと有効になります。",
    },
    allow: {
      title: "トンネル経由の接続を許可するプライベートネットワーク",
      label: "CIDR リスト",
      hint: "1 行に 1 つ。例：10.64.0.0/10 や fd00::/8。WireGuard 設定の AllowedIPs の範囲内でなければ到達できません。",
    },
    firewall: {
      title: "ファイアウォールの許可ルール",
      note: "空欄なら制限しません。1 つでも指定すると、それ以外の宛先やポートはすべて拒否されます（既定で拒否）。",
      destinations: "許可する宛先",
      destinationsHint:
        "1 行に 1 つの CIDR。例：203.0.113.0/24。0.0.0.0/0 はすべての IPv4 を表します（同時にすべての IPv6 を拒否します）。",
      privateWarning: (nets) =>
        `${nets.join("、")} はプライベートネットワークです。通すには、上の「トンネル経由の接続を許可するプライベートネットワーク」にも指定してください`,
      destinationsPlaceholder: "空欄：任意の公開アドレス",
      ports: "許可する宛先ポート",
      portsHint: "カンマまたはスペースで区切ります。範囲も使えます。例：80, 443, 8000-8999。",
      portsPlaceholder: "空欄：任意のポート",
    },
    ports: {
      title: "ブロックする宛先ポート",
      field: "ポート",
      hint: "カンマまたはスペースで区切ります。これらのポートへのプロキシ接続は拒否されます（許可した範囲内でも）。",
      allListed: "すべて指定済みです",
      presets: {
        smtp: "メール送信（SMTP）",
        windowsSharing: "Windows ファイル共有",
        remoteDesktop: "リモートデスクトップ",
      },
    },
    manageLists: "リストを管理",
    autoBan: {
      title: "自動ブロック",
      log: "ブロック記録",
      switchLabel: "短時間に新しい接続を開きすぎる送信元をブロック",
      switchHint:
        "ポート転送経由で着信した新しい接続だけを数えます（ログイン失敗の回数ではありません）。ブロック中はその送信元から再び着信できず、ゲートウェイ経由でその送信元へ接続することも拒否されます。接続に必要な WireGuard のピアと DNS サーバーは決してブロックされません。",
      forwardsUnknown: "ポート転送があるか確認できません",
      unused: "このセキュリティ設定を使用している接続はありません",
      unusedBody: "接続がこの設定を使い始めてから、自動ブロックのカウントが始まります。",
      noForwards: "この設定を使用している接続にはポート転送がありません",
      noForwardsBody: (link) => (
        <>自動ブロックはポート転送経由で着信した接続だけを見ます。{link}するまで、どの送信元もブロックしません。</>
      ),
      createForward: "ポート転送を作成",
      forwards: (total, enabled) =>
        `この設定を使用している接続には、ポート転送が計 ${total} 件あります（有効 ${enabled} 件）。`,
      field: (label, unit) => `${label}（${unit}）`,
      summary: (on, windowSecs, threshold, banSecs, max) =>
        `${on ? "" : "有効にすると、"}同じ送信元が ${windowSecs} 秒以内に ${threshold} 件を超える新しい接続を開くと、${banSecs} 秒間ブロックします。同時にブロックする送信元は最大 ${max} 件です。設定は接続の再起動後に有効になります。`,
    },
    errors: {
      allowFormat: (bad) => `形式が正しくありません：${bad.join("、")}（CIDR が必要です。例：10.64.0.0/10）`,
      allowSpecial: (nets) =>
        `ループバック、リンクローカル、マルチキャスト、アドレス空間全体は許可できません：${nets.join("、")}`,
      atMostNetworks: (max) => `最大 ${max} 個です`,
      format: (bad) => `形式が正しくありません：${bad.join("、")}`,
      destSpecial: (nets) =>
        `ループバック、リンクローカル、マルチキャストのアドレスは許可できません：${nets.join("、")}`,
      portRange: (bad) => `無効なポートまたは範囲：${bad.join("、")}（例：443 や 8000-8999）`,
      atMostRanges: (max) => `最大 ${max} 組です`,
      port: (bad) => `無効なポート：${bad.join("、")}`,
      atMostPorts: (max) => `最大 ${max} 個です`,
      atMostLists: (max) => `選択できるのは最大 ${max} 件です`,
      overlayTooLarge: "選択したリストを合わせると上限の 16 MiB を超えます。リストを減らしてください",
    },
    actions: {
      deleting: "「削除」を送信中です。完了してから操作してください",
      inUse: (count) => `${count} 件の接続がこの設定を使用しています。先に別のセキュリティ設定に切り替えてください`,
      deleted: (name) => `セキュリティ設定 ${name} を削除しました`,
      deleteIntent: (name) => `${name} の削除`,
    },
    deleteConfirm: {
      title: (name) => `セキュリティ設定「${name}」を削除しますか？`,
      body: (lists) =>
        `この設定のルール${lists ? `と IP ブロックリスト ${lists} 件の選択` : ""}は一緒に削除されます。リストそのものには影響しません。この設定を使用している接続はないため、どの接続にも影響しません。`,
    },
    model: {
      autoBan: {
        window: { label: "カウント期間", unit: "秒" },
        threshold: { label: "新しい接続のしきい値", unit: "件" },
        ban: { label: "ブロック時間", unit: "秒" },
        maxBans: { label: "同時ブロック数の上限", unit: "件" },
        notWhole: (label) => `${label}は整数で入力してください`,
        outOfRange: (label, min, max, unit) => `${label}は ${min}～${max} ${unit}の範囲で入力してください`,
      },
      allowRangesName: (ranges) => `${ranges.join("、")} を許可`,
      about: (mantissa, exponent) => `約 ${mantissa} × 10^${exponent}`,
      entries: (text) => `${text} 件`,
      ranges: (family, text) => `${family} ${text} 範囲`,
      source: { upload: "アップロード", url: "URL" },
      format: {
        plain: "1 行に 1 つのアドレスまたは CIDR",
        json_lines: "JSON lines（1 行に 1 つの cidr）",
        tab_ranges: "タブ区切りの開始・終了アドレスとマスク",
      },
      bothFamilies: "IPv4＋IPv6",
      state: {
        waiting: "Provider 出口を待機中",
        firstFailed: "初回のダウンロードに失敗",
        awaiting: "ダウンロード待ち",
        refreshFailed: "更新に失敗",
      },
      refresh: {
        manual: "手動更新のみ",
        daily: "毎日",
        weekly: "毎週",
        every: (hours) => `${hours} 時間ごと`,
      },
      duration: {
        days: (days, hours) => `${days} 日 ${hours} 時間`,
        hours: (hours, minutes) => `${hours} 時間 ${minutes} 分`,
        minutes: (minutes, seconds) => `${minutes} 分 ${seconds} 秒`,
        seconds: (seconds) => `${seconds} 秒`,
      },
      banSort: { newest: "ブロック日時", expiry: "残り時間" },
    },
  },
});
