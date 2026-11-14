// Text of the DNS profiles page (DNS 設定): the list, a profile's editor, its actions and the NextDNS dialog; the names
// of the preset resolvers (presets.ts, which the connection dialog offers too); and under `restart` the callout and
// confirmation that restart the running connections still on an earlier version of a saved DNS or security profile
// (restart-users.tsx, which the security profiles page shows too).

import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** “A”, “B”, and “C”. */
function quotedEn(names: readonly string[]): string {
  return listEn.format(names.map((name) => `“${name}”`));
}

/** 「A」、「B」、「C」. */
function quotedCjk(names: readonly string[]): string {
  return names.map((name) => `「${name}」`).join("、");
}

/** "connection" or "connections", by the count. */
const connections = (count: number) => (count === 1 ? "connection" : "connections");

export const m = defineMessages({
  en: {
    title: "DNS profiles",
    description:
      "The servers a connection resolves domain names with; every query leaves through that connection's tunnel.",
    help: "This machine's system DNS is never used. A connection without a DNS profile uses the DNS its WireGuard configuration file declares: queries go out over UDP and are asked again over TCP only when an answer comes back truncated. A connection whose configuration file declares no DNS needs a DNS profile to start. When none of a DNS profile's servers answers, the profile's own choice applies: the connections that use it switch for the time being to the DNS their WireGuard configuration file declares (also through the tunnel), or name resolution stops and no other DNS is asked. Either way the connection's state says so, and it returns to normal by itself once the servers answer again. Saved changes apply once the connections that use the profile restart.",
    helpText:
      "This machine's system DNS is never used; saved changes apply once the connections that use the profile restart.",
    add: "Add DNS profile",
    newProfile: "New DNS profile",
    loading: "Loading DNS profiles",
    notFound: "This DNS profile was not found",
    /** The list could not be refreshed: `time` is when the data on screen was read. */
    stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
    actionsOf: (name: string) => `Actions for ${name}`,
    moreActionsOf: (name: string) => `More actions for ${name}`,
    /** How many connections use a profile (a tag beside its name). */
    usedBy: (count: number): string =>
      count === 0 ? "No connection uses it" : count === 1 ? "Used by 1 connection" : `Used by ${count} connections`,
    /** A profile in one line: its servers, their protocols, and whether resolution stops while all of them fail. */
    summary: (servers: number, protocols: readonly string[], stops: boolean): string =>
      `${servers} ${servers === 1 ? "server" : "servers"} · ${protocols.join("/")}${stops ? " · stops resolving on failure" : ""}`,
    list: {
      /** The list's navigation and its items. */
      label: "DNS profiles",
      listLabel: "List of DNS profiles",
      /** The detail pane while no profile is open. */
      detail: "DNS profile",
      all: "All DNS profiles",
      settingsOf: (name: string) => `Settings of ${name}`,
      /** A row's second line: the profile's summary, then how many connections use it. */
      meta: (summary: string, users: number): string =>
        users ? `${summary} · ${users} ${connections(users)}` : summary,
      choose: "Choose a DNS profile",
      chooseDetail: "See and edit its servers, query deadline and cache, and the connections that use it.",
      none: "No DNS profiles of your own yet",
      noneDetail:
        "A connection without a DNS profile uses the DNS its WireGuard configuration file declares, also queried through the tunnel. A connection whose configuration file declares no DNS needs a DNS profile to start.",
      noneCompact: "Connections without one use the DNS their configuration file declares.",
    },
    users: {
      title: "Connections using it",
      label: "Connections that use this DNS profile",
      appliesAfterRestart: "Applies after a restart",
      none: "No connection uses this profile; it takes effect once a connection's settings select it.",
    },
    editor: {
      description: "Resolvers tried in order, the query deadline and the cache.",
      idLabel: "DNS profile ID",
      appliesOnRestart: "Saved changes apply once the connections that use it restart.",
      unused: "No connection uses it yet; select it in a connection's settings.",
      afterCreating: "Once created, it can be selected in a connection's settings.",
      namePlaceholder: "For example: encrypted DNS (DoT)",
      servers: "Servers",
      presets: "Common servers",
      addPreset: "Add a common server",
      nextDns: "NextDNS (configuration ID)…",
      atMost: (max: number) => `At most ${max} servers`,
      /** Under the servers' heading. */
      serversNote: (max: number) =>
        `Tried in order (at most ${max}), all within one query deadline; every query leaves through the tunnel and never falls back to the system DNS. Choose below what happens when none of them answers; the connection's state shows it.`,
      serverList: "DNS servers (tried in order)",
      protocolOf: (n: number) => `Protocol of server ${n}`,
      addressOf: (n: number) => `Address of server ${n}`,
      addressPlaceholder: (port: number) => `IP:port, for example 10.64.0.1:${port}`,
      moveUp: (n: number) => `Move server ${n} up`,
      alreadyFirst: "Already the first",
      moveDown: (n: number) => `Move server ${n} down`,
      alreadyLast: "Already the last",
      remove: (n: number) => `Remove server ${n}`,
      lastOne: "There has to be at least one server",
      serverNameOf: (n: number) => `Certificate host name of server ${n}`,
      serverNamePlaceholder: "Certificate host name, for example dns.quad9.net",
      urlOf: (n: number) => `DoH URL of server ${n}`,
      addServer: "Add server",
      /** What a connection does while every server fails (the profile's `on_failure`), and what that means for it. */
      onFailure: {
        label: "When every server fails",
        wireguard_resolvers: {
          title: "Use the WireGuard profile's DNS instead",
          text: "Names still resolve, but through the VPN provider's DNS for that time.",
        },
        fail: {
          title: "Stop resolving until a server recovers",
          text: "For that time the connection's apps cannot resolve names; no other DNS is asked.",
        },
      },
      numbers: "Queries and cache",
      timeout: "Query deadline (ms)",
      timeoutHint: "Shared by all attempts; through a distant exit with DoT or DoH, 5000 or more is recommended",
      attempts: "Attempts",
      maxEntries: "Cache entry limit",
      maxTtl: "Maximum cache time (s)",
      negativeTtl: "Negative caching (s)",
      negativeTtlHint: "How long a not-found result is kept",
      saved: (name: string) => `Saved ${name}`,
      created: (name: string) => `Created ${name}`,
      errors: {
        address: "Enter IP:port, for example 10.64.0.1:53",
        serverName: "DoT needs the certificate host name",
        url: "A DoH URL must start with https://",
        wholeNumber: "Enter a whole number",
      },
    },
    actions: {
      deleting: "“Delete” is being sent; wait until it is done",
      inUse: (count: number): string =>
        count === 1
          ? "1 connection uses this profile: switch it to another DNS profile first"
          : `${count} connections use this profile: switch them to another DNS profile first`,
      deleted: (name: string) => `Deleted DNS profile ${name}`,
      /** What a failed deletion is reported as (the notification adds that it failed). */
      deleteIntent: (name: string) => `Delete ${name}`,
    },
    deleteConfirm: {
      title: (name: string) => `Delete the DNS profile “${name}”?`,
      /** What goes with the profile (only a profile no connection uses can be deleted). */
      body: (servers: number): string =>
        `${servers === 1 ? "Its server" : `Its ${servers} servers`} and cache settings are deleted with it. No connection uses this profile, so no connection is affected.`,
    },
    nextDns: {
      title: "Use NextDNS",
      description:
        "Generates 4 encrypted servers from a NextDNS configuration ID (DoH and DoT, two anycast addresses each) that replace the current server list; they take effect once this DNS profile is created or saved.",
      apply: "Apply",
      id: "Configuration ID",
      idHint: "The ID on the Setup page of the NextDNS website",
      idPlaceholder: "For example: abc123",
      device: "Device name",
      deviceHint: "Optional: shown in NextDNS's logs to tell this connection apart",
      devicePlaceholder: "For example: office-pc",
      servers: "Servers to be used (tried in order)",
      serversLabel: "Servers to be used",
      serversLater: "Shown once a configuration ID is entered.",
      errors: {
        idMissing: "Enter the NextDNS configuration ID",
        idFormat: "A configuration ID is 6 characters (0–9, a–f), for example abc123",
        device: "Use only letters, digits and hyphens (not first or last), at most 56 characters",
      },
      /** The profile name the preset suggests: `NextDNS (abc123) · office-pc`. */
      profileName: (id: string, device: string) => `NextDNS (${id})${device ? ` · ${device}` : ""}`,
    },
    presets: {
      mullvad: "Mullvad (in the tunnel, 10.64.0.1)",
      /** A plain-DNS resolver inside the tunnel, by its address. */
      inner: (ip: string) => `Internal DNS ${ip}`,
    },
    /** Running connections that still use an earlier version of a saved DNS or security profile. */
    restart: {
      /** The callout's title. */
      stillEarlier: (count: number): string =>
        count === 1
          ? "1 running connection still uses the earlier version"
          : `${count} running connections still use the earlier version`,
      /** The callout's action: the same words as the notification after saving. */
      offer: (count: number) => `Restart the ${count} ${connections(count)} using it`,
      /** The callout's text: `names` are the connections that wait for a restart. */
      waiting: (names: readonly string[]): string =>
        names.length === 1
          ? `${quotedEn(names)} takes the saved settings only after it restarts.`
          : `${quotedEn(names)} take the saved settings only after they restart.`,
      confirmTitle: (count: number): string =>
        count === 1 ? "Restart 1 connection?" : `Restart ${count} connections?`,
      confirm: (count: number): string => (count === 1 ? "Restart 1 connection" : `Restart ${count} connections`),
      /** What the restart does, by the kind of profile that was saved. */
      rebuilt: (names: readonly string[], kind: "dns" | "security"): string =>
        `${quotedEn(names)} ${names.length === 1 ? "is" : "are"} rebuilt with the saved ${kind === "dns" ? "DNS profile" : "security profile"}.`,
      interrupts: (count: number): string =>
        count === 1
          ? "While it restarts, the connections it carries now are cut and new ones are refused, never falling back to the ordinary network; other connections are not affected."
          : "While they restart, the connections they carry now are cut and new ones are refused, never falling back to the ordinary network; other connections are not affected.",
    },
  },
  "zh-TW": {
    title: "DNS 設定",
    description: "連線內部用來解析網域的伺服器；查詢一律經該連線的 tunnel 送出。",
    help: "不會使用本機的系統 DNS。沒有指定 DNS 設定的連線，使用 WireGuard 設定檔宣告的 DNS：以 UDP 送出，只有回應被截斷時才改用 TCP 重問；設定檔沒有宣告 DNS 的連線，必須指定 DNS 設定才能啟動。DNS 設定的伺服器全部沒有回應時，依每份設定的選擇：使用它的連線暫時改用 WireGuard 設定檔宣告的 DNS（同樣經 tunnel），或中斷名稱解析、不問其他 DNS；兩者都在連線的狀態中標示，伺服器恢復回應後自動恢復。儲存的變更在使用它的連線重新啟動後套用。",
    helpText: "不會使用本機的系統 DNS；儲存的變更在使用它的連線重新啟動後套用。",
    add: "新增 DNS 設定",
    newProfile: "新的 DNS 設定",
    loading: "載入 DNS 設定",
    notFound: "找不到這份 DNS 設定",
    stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
    actionsOf: (name) => `${name} 的操作`,
    moreActionsOf: (name) => `${name} 的更多操作`,
    usedBy: (count) => (count ? `${count} 條連線使用` : "沒有連線使用"),
    summary: (servers, protocols, stops) =>
      `${servers} 個伺服器 · ${protocols.join("／")}${stops ? " · 失敗時中斷" : ""}`,
    list: {
      label: "DNS 設定",
      listLabel: "DNS 設定清單",
      detail: "DNS 設定",
      all: "所有 DNS 設定",
      settingsOf: (name) => `${name} 的設定`,
      meta: (summary, users) => `${summary}${users ? ` · ${users} 條連線` : ""}`,
      choose: "選擇一份 DNS 設定",
      chooseDetail: "查看與編輯它的伺服器、查詢期限與快取，以及使用它的連線。",
      none: "還沒有自訂 DNS 設定",
      noneDetail:
        "沒有指定 DNS 設定的連線，會使用 WireGuard 設定檔宣告的 DNS，同樣經 tunnel 查詢。設定檔沒有宣告 DNS 的連線，必須指定 DNS 設定才能啟動。",
      noneCompact: "沒有指定的連線使用設定檔宣告的 DNS。",
    },
    users: {
      title: "使用中的連線",
      label: "使用這份 DNS 設定的連線",
      appliesAfterRestart: "重新啟動後套用",
      none: "沒有連線使用這份設定；在連線的設定中選用後才會生效。",
    },
    editor: {
      description: "依序嘗試的解析伺服器、查詢期限與快取。",
      idLabel: "DNS 設定 ID",
      appliesOnRestart: "儲存的變更在使用它的連線重新啟動後套用。",
      unused: "還沒有連線使用；在連線的設定中選用。",
      afterCreating: "建立後可以在連線的設定中選用。",
      namePlaceholder: "例如：加密 DNS（DoT）",
      servers: "伺服器",
      presets: "常用伺服器",
      addPreset: "加入常用伺服器",
      nextDns: "NextDNS（設定 ID）…",
      atMost: (max) => `最多 ${max} 個伺服器`,
      serversNote: (max) =>
        `依序嘗試（最多 ${max} 個），在同一個查詢期限內完成；所有查詢都經 tunnel 送出，不會退回系統 DNS。全部沒有回應時怎麼做，在下方選擇；連線的狀態會標示。`,
      serverList: "DNS 伺服器（依序嘗試）",
      protocolOf: (n) => `第 ${n} 個伺服器的協定`,
      addressOf: (n) => `第 ${n} 個伺服器的位址`,
      addressPlaceholder: (port) => `IP:埠，例如 10.64.0.1:${port}`,
      moveUp: (n) => `第 ${n} 個伺服器上移`,
      alreadyFirst: "已經是第一個",
      moveDown: (n) => `第 ${n} 個伺服器下移`,
      alreadyLast: "已經是最後一個",
      remove: (n) => `移除第 ${n} 個伺服器`,
      lastOne: "至少要有一個伺服器",
      serverNameOf: (n) => `第 ${n} 個伺服器的憑證主機名稱`,
      serverNamePlaceholder: "憑證主機名稱，例如 dns.quad9.net",
      urlOf: (n) => `第 ${n} 個伺服器的 DoH URL`,
      addServer: "新增伺服器",
      onFailure: {
        label: "伺服器全部失敗時",
        wireguard_resolvers: {
          title: "改用 WireGuard 設定的 DNS",
          text: "名稱照常解析，但這段時間改經 VPN 供應商的 DNS。",
        },
        fail: {
          title: "中斷，直到伺服器恢復",
          text: "這段時間連線的 App 無法解析名稱，不會改問其他 DNS。",
        },
      },
      numbers: "查詢與快取",
      timeout: "查詢期限（毫秒）",
      timeoutHint: "所有嘗試共用；經遠的出口使用 DoT 或 DoH 時，建議 5000 以上",
      attempts: "嘗試次數",
      maxEntries: "快取筆數上限",
      maxTtl: "最長快取（秒）",
      negativeTtl: "否定快取（秒）",
      negativeTtlHint: "查無結果的保留時間",
      saved: (name) => `已儲存 ${name}`,
      created: (name) => `已建立 ${name}`,
      errors: {
        address: "請輸入 IP:埠，例如 10.64.0.1:53",
        serverName: "DoT 需要憑證主機名稱",
        url: "DoH URL 必須以 https:// 開頭",
        wholeNumber: "請輸入整數",
      },
    },
    actions: {
      deleting: "正在送出「刪除」，完成後再操作",
      inUse: (count) => `${count} 條連線使用這份設定：先讓它們改用其他 DNS 設定`,
      deleted: (name) => `已刪除 DNS 設定 ${name}`,
      deleteIntent: (name) => `刪除 ${name}`,
    },
    deleteConfirm: {
      title: (name) => `刪除 DNS 設定「${name}」？`,
      body: (servers) => `它的 ${servers} 個伺服器與快取設定會一起刪除。沒有連線使用這份設定，所以不影響任何連線。`,
    },
    nextDns: {
      title: "使用 NextDNS",
      description:
        "依 NextDNS 的設定 ID 產生 4 個加密伺服器（DoH 與 DoT，各兩個 anycast 位址），取代目前的伺服器清單；建立或儲存這份 DNS 設定後才生效。",
      apply: "套用",
      id: "設定 ID",
      idHint: "NextDNS 網站「設定」頁上的 ID",
      idPlaceholder: "例如 abc123",
      device: "裝置名稱",
      deviceHint: "選填：顯示在 NextDNS 的紀錄中，區分這條連線",
      devicePlaceholder: "例如 office-pc",
      servers: "將使用的伺服器（依序嘗試）",
      serversLabel: "將使用的伺服器",
      serversLater: "輸入設定 ID 後顯示。",
      errors: {
        idMissing: "請輸入 NextDNS 的設定 ID",
        idFormat: "設定 ID 是 6 個英數字（0–9、a–f），例如 abc123",
        device: "只能用英文字母、數字與連字號（不能在頭尾），最多 56 個字元",
      },
      profileName: (id, device) => `NextDNS（${id}）${device ? `· ${device}` : ""}`,
    },
    presets: {
      mullvad: "Mullvad（tunnel 內，10.64.0.1）",
      inner: (ip) => `內部 DNS ${ip}`,
    },
    restart: {
      stillEarlier: (count) => `${count} 條執行中的連線仍使用先前的版本`,
      offer: (count) => `重新啟動使用中的 ${count} 條連線`,
      waiting: (names) => `${quotedCjk(names)}重新啟動後才會套用儲存的設定。`,
      confirmTitle: (count) => `重新啟動 ${count} 條連線？`,
      confirm: (count) => `重新啟動 ${count} 條連線`,
      rebuilt: (names, kind) => `${quotedCjk(names)}會以儲存的${kind === "dns" ? " DNS " : "安全"}設定重新建立。`,
      interrupts: () => "重新啟動期間它們目前的連線會中斷、新連線會被拒絕，不會改走一般網路；其他連線不受影響。",
    },
  },
  ja: {
    title: "DNS 設定",
    description:
      "接続の内部でドメイン名の名前解決に使うサーバー。問い合わせはすべてその接続のトンネル経由で送信されます。",
    help: "ローカルのシステム DNS は使用しません。DNS 設定を指定していない接続は、WireGuard 設定ファイルで宣言された DNS を使います。問い合わせは UDP で送信し、応答が切り詰められたときだけ TCP で問い合わせ直します。設定ファイルで DNS が宣言されていない接続は、DNS 設定を指定しないと開始できません。DNS 設定のサーバーがすべて応答しないときは、設定ごとの選択に従います。使用している接続が一時的に WireGuard 設定ファイルで宣言された DNS（同じくトンネル経由）に切り替えるか、名前解決を中断してほかの DNS には問い合わせません。どちらの場合も接続の状態に表示され、サーバーが応答を再開すると自動的に元に戻ります。保存した変更は、使用している接続が再起動すると適用されます。",
    helpText: "ローカルのシステム DNS は使用しません。保存した変更は、使用している接続が再起動すると適用されます。",
    add: "DNS 設定を追加",
    newProfile: "新しい DNS 設定",
    loading: "DNS 設定を読み込み中",
    notFound: "この DNS 設定が見つかりません",
    stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
    actionsOf: (name) => `${name} の操作`,
    moreActionsOf: (name) => `${name} のその他の操作`,
    usedBy: (count) => (count ? `${count} 件の接続が使用中` : "使用中の接続なし"),
    summary: (servers, protocols, stops) =>
      `サーバー ${servers} 台 · ${protocols.join("／")}${stops ? " · 失敗時は中断" : ""}`,
    list: {
      label: "DNS 設定",
      listLabel: "DNS 設定の一覧",
      detail: "DNS 設定",
      all: "すべての DNS 設定",
      settingsOf: (name) => `${name} の設定`,
      meta: (summary, users) => `${summary}${users ? ` · ${users} 件の接続` : ""}`,
      choose: "DNS 設定を選択",
      chooseDetail: "サーバー、問い合わせ期限、キャッシュと、それを使用している接続を確認・編集できます。",
      none: "自分の DNS 設定はまだありません",
      noneDetail:
        "DNS 設定を指定していない接続は、WireGuard 設定ファイルで宣言された DNS を使い、同じくトンネル経由で問い合わせます。設定ファイルで DNS が宣言されていない接続は、DNS 設定を指定しないと開始できません。",
      noneCompact: "指定していない接続は、設定ファイルで宣言された DNS を使います。",
    },
    users: {
      title: "使用中の接続",
      label: "この DNS 設定を使用している接続",
      appliesAfterRestart: "再起動後に適用",
      none: "この設定を使用している接続はありません。接続の設定で選ぶと有効になります。",
    },
    editor: {
      description: "順に試すリゾルバー、問い合わせ期限、キャッシュ。",
      idLabel: "DNS 設定 ID",
      appliesOnRestart: "保存した変更は、これを使用している接続が再起動すると適用されます。",
      unused: "まだ使用している接続はありません。接続の設定で選んでください。",
      afterCreating: "作成後、接続の設定で選べます。",
      namePlaceholder: "例：暗号化 DNS（DoT）",
      servers: "サーバー",
      presets: "よく使うサーバー",
      addPreset: "よく使うサーバーを追加",
      nextDns: "NextDNS（設定 ID）…",
      atMost: (max) => `サーバーは最大 ${max} 台です`,
      serversNote: (max) =>
        `順に試します（最大 ${max} 台）。すべて同じ問い合わせ期限内に行い、問い合わせはすべてトンネル経由で送信され、システムの DNS に戻ることはありません。どれも応答しないときの動作は下で選びます。接続の状態に表示されます。`,
      serverList: "DNS サーバー（順に試行）",
      protocolOf: (n) => `${n} 番目のサーバーのプロトコル`,
      addressOf: (n) => `${n} 番目のサーバーのアドレス`,
      addressPlaceholder: (port) => `IP:ポート（例：10.64.0.1:${port}）`,
      moveUp: (n) => `${n} 番目のサーバーを上へ移動`,
      alreadyFirst: "すでに先頭です",
      moveDown: (n) => `${n} 番目のサーバーを下へ移動`,
      alreadyLast: "すでに末尾です",
      remove: (n) => `${n} 番目のサーバーを削除`,
      lastOne: "サーバーは 1 台以上必要です",
      serverNameOf: (n) => `${n} 番目のサーバーの証明書ホスト名`,
      serverNamePlaceholder: "証明書のホスト名（例：dns.quad9.net）",
      urlOf: (n) => `${n} 番目のサーバーの DoH URL`,
      addServer: "サーバーを追加",
      onFailure: {
        label: "すべてのサーバーが失敗したとき",
        wireguard_resolvers: {
          title: "WireGuard 設定の DNS に切り替え",
          text: "名前解決は通常どおり行われますが、その間は VPN プロバイダーの DNS を経由します。",
        },
        fail: {
          title: "サーバーが回復するまで中断",
          text: "その間、接続のアプリは名前解決できず、ほかの DNS には問い合わせません。",
        },
      },
      numbers: "問い合わせとキャッシュ",
      timeout: "問い合わせ期限（ミリ秒）",
      timeoutHint: "すべての試行で共有します。遠い出口で DoT や DoH を使うときは 5000 以上を推奨します",
      attempts: "試行回数",
      maxEntries: "キャッシュ件数の上限",
      maxTtl: "最長キャッシュ時間（秒）",
      negativeTtl: "ネガティブキャッシュ（秒）",
      negativeTtlHint: "結果なしの応答を保持する時間",
      saved: (name) => `${name} を保存しました`,
      created: (name) => `${name} を作成しました`,
      errors: {
        address: "IP:ポートを入力してください（例：10.64.0.1:53）",
        serverName: "DoT には証明書のホスト名が必要です",
        url: "DoH URL は https:// で始める必要があります",
        wholeNumber: "整数を入力してください",
      },
    },
    actions: {
      deleting: "「削除」を送信中です。完了してから操作してください",
      inUse: (count) => `${count} 件の接続がこの設定を使用しています。先に別の DNS 設定に切り替えてください`,
      deleted: (name) => `DNS 設定 ${name} を削除しました`,
      deleteIntent: (name) => `${name} の削除`,
    },
    deleteConfirm: {
      title: (name) => `DNS 設定「${name}」を削除しますか？`,
      body: (servers) =>
        `この設定の ${servers} 台のサーバーとキャッシュ設定も一緒に削除されます。この設定を使用している接続はないため、どの接続にも影響しません。`,
    },
    nextDns: {
      title: "NextDNS を使用",
      description:
        "NextDNS の設定 ID から暗号化サーバーを 4 台生成し（DoH と DoT、それぞれ 2 つの anycast アドレス）、現在のサーバー一覧と置き換えます。この DNS 設定を作成または保存すると有効になります。",
      apply: "適用",
      id: "設定 ID",
      idHint: "NextDNS サイトの「セットアップ」ページにある ID",
      idPlaceholder: "例：abc123",
      device: "デバイス名",
      deviceHint: "任意：NextDNS のログに表示され、この接続を区別できます",
      devicePlaceholder: "例：office-pc",
      servers: "使用するサーバー（順に試行）",
      serversLabel: "使用するサーバー",
      serversLater: "設定 ID を入力すると表示されます。",
      errors: {
        idMissing: "NextDNS の設定 ID を入力してください",
        idFormat: "設定 ID は 6 文字の英数字（0–9、a–f）です。例：abc123",
        device: "英字、数字、ハイフン（先頭と末尾を除く）だけを使い、56 文字以内にしてください",
      },
      profileName: (id, device) => `NextDNS（${id}）${device ? `· ${device}` : ""}`,
    },
    presets: {
      mullvad: "Mullvad（トンネル内、10.64.0.1）",
      inner: (ip) => `内部 DNS ${ip}`,
    },
    restart: {
      stillEarlier: (count) => `実行中の ${count} 件の接続が、まだ以前のバージョンを使用しています`,
      offer: (count) => `使用中の ${count} 件の接続を再起動`,
      waiting: (names) => `${quotedCjk(names)}は、再起動すると保存した設定が適用されます。`,
      confirmTitle: (count) => `${count} 件の接続を再起動しますか？`,
      confirm: (count) => `${count} 件の接続を再起動`,
      rebuilt: (names, kind) =>
        `${quotedCjk(names)}は保存した${kind === "dns" ? " DNS " : "セキュリティ"}設定で再構築されます。`,
      interrupts: () =>
        "再起動中は現在の通信が切断され、新しい通信は拒否されます。通常のネットワークに切り替わることはありません。ほかの接続には影響しません。",
    },
  },
});
