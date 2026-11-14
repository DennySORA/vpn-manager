// Text of the transport profiles page (傳輸設定): the list, a built-in profile's values, a saved profile's editor and
// the profile actions, and under `model` the lines `model.ts` writes about a profile (the connection pages show them
// too). The names and one-sentence summaries of the built-in profiles come from the service and are shown as they
// arrive.

import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** “A”, “B”, and “C”. */
function quotedEn(names: readonly string[]): string {
  return listEn.format(names.map((name) => `“${name}”`));
}

/** 「A」、「B」、「C」. */
function quotedCjk(names: readonly string[]): string {
  return `「${names.join("」、「")}」`;
}

export const m = defineMessages({
  en: {
    title: "Transport profiles",
    description:
      "Each connection's buffers, TCP behavior, timeouts and health probe; one fixed set, or switched automatically by round-trip time.",
    help: "Each connection uses one transport profile: the built-in automatic one unless another is chosen. A fixed profile is one set of values. An automatic profile picks a fixed profile for each range of round-trip times: the connections opened after a measurement use the profile of the range the measured round-trip time falls in. A buffer's limit sets the speed limit of one connection (buffer ÷ round-trip time); a connection opens at the initial size and grows only while it transfers fast, using no more than three quarters of the connection buffer budget and leaving the rest for new connections. A saved profile applies at once to connections opened from then on, without a restart; connections already open stay as they are. With strict isolation the Linux kernel sizes the buffers itself, and the limit here only raises the kernel's limit.",
    helpText:
      "A saved profile applies at once to connections opened from then on, without a restart; connections already open stay as they are.",
    add: "Add transport profile",
    newProfile: "New transport profile",
    loading: "Loading transport profiles",
    notFound: "This transport profile was not found",
    /** The list could not be refreshed: `time` is when the data on screen was read. */
    stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
    actionsOf: (name: string) => `Actions for ${name}`,
    moreActionsOf: (name: string) => `More actions for ${name}`,
    /** How many connections use a profile (a tag beside its name). */
    usedBy: (count: number) =>
      count === 0 ? "No connection uses it" : count === 1 ? "Used by 1 connection" : `Used by ${count} connections`,
    list: {
      label: "List of transport profiles",
      builtIn: "Built-in transport profiles",
      mine: "My profiles",
      mineLabel: "My transport profiles",
      noneOfMine:
        "No profiles of your own yet. Open a built-in profile and choose “Duplicate to my profiles” to start from it.",
      all: "All transport profiles",
      /** The detail pane while no profile is open. */
      detail: "Transport profile",
      settingsOf: (name: string) => `Settings of ${name}`,
      /** A row's second line: what the profile holds, then how many connections use it. */
      meta: (brief: string, users: number) =>
        users ? `${brief} · ${users} ${users === 1 ? "connection" : "connections"}` : brief,
    },
    users: {
      title: "Connections using it",
      label: "Connections that use this transport profile",
      /** The range an automatic profile's connection is in now, by the name of the range's profile. */
      range: (name: string) => `Now “${name}”`,
      none: "No connection uses this profile; it takes effect once a connection's settings select it.",
    },
    values: {
      byRoundTrip: "Chosen by round-trip time",
      measuring:
        "Each time the connection opens a TCP connection it measures the round-trip time (the time the handshake takes) and takes the median of the latest few. Connections opened after that use the profile of the range it falls in; connections already open are not affected.",
      fromRoundTrip: (ms: number) => `From ${ms} ms`,
      tcpBuffers: "TCP buffers",
      send: "Send",
      receive: "Receive",
      ceiling: (roundTripMs: number, upload: string, download: string) =>
        `At a round trip of ${roundTripMs} ms, one connection uploads at most about ${upload} MB/s and downloads about ${download} MB/s (buffer ÷ round-trip time).`,
      tcpBehavior: "TCP behavior and timeouts",
      congestion: "Congestion control",
      on: "On",
      off: "Off",
      delayedAck: "Delayed ACK",
      connectTimeout: "Connect timeout",
      keepalive: "Keepalive",
      every: (secs: number) => `Every ${secs} s`,
      deadPeer: "No-response timeout",
      udpBuffer: "UDP buffer",
      perDirection: "Per direction",
      health: "Health probe",
      probeInterval: "Probe interval",
      failures: "Consecutive failures",
      failuresMeaning: "At this many, new connections are no longer accepted until the probe recovers",
      failureCount: (count: number) => String(count),
      handshakeTimeout: "Handshake timeout",
      handshakeMeaning: "How long a start waits for the first WireGuard handshake",
      secs: (secs: number) => `${secs} s`,
      ms: (ms: number) => `${ms} ms`,
    },
    builtIn: {
      note: "Built-in profiles are part of the program and cannot be changed; duplicate one to adjust every value.",
    },
    editor: {
      duplicating: (name: string) => `Duplicate “${name}”`,
      /** The name a copy starts with. */
      copyName: (name: string) => `Copy of ${name}`,
      description: "A connection's buffers, TCP behavior and timeouts, and how its health is probed.",
      idLabel: "Transport profile ID",
      appliesAtOnce:
        "Applied as soon as it is saved: the connections that use it apply the new values to the connections they open from then on, without a restart.",
      unused: "No connection uses it yet; select it in a connection's settings.",
      afterCreating: "Once created, it can be selected in a connection's settings.",
      namePlaceholder: "For example: double VPN upload",
      kind: "Kind of profile",
      fixed: "Fixed",
      fixedTitle: "One fixed set of values",
      fixedNote: "One fixed set of values, used whatever is measured.",
      automatic: "Automatic",
      automaticTitle: "Picks a different fixed profile by the measured round-trip time",
      automaticNote: "Picks one fixed profile for each range of the measured round-trip time.",
      /** Shown on a profile switched to automatic while a range of another automatic profile uses it. */
      mustStayFixed: (names: readonly string[]) =>
        names.length === 1
          ? `A range of the automatic profile ${quotedEn(names)} uses this profile: it has to stay fixed, and saving will be refused.`
          : `Ranges of the automatic profiles ${quotedEn(names)} use this profile: it has to stay fixed, and saving will be refused.`,
      buffers:
        "The buffer sets the speed limit of one connection. A connection opens at the initial size (the connection buffer it takes as soon as it opens) and doubles, step by step up to the limit, only when it transfers fast enough; a connection that does not need more stays at the initial size.",
      sendStart: "Send: initial",
      sendLimit: "Send: limit",
      uploadDirection: "Upload direction",
      receiveStart: "Receive: initial",
      receiveLimit: "Receive: limit",
      downloadDirection: "Download direction",
      strictIsolation:
        "With strict isolation the Linux kernel sizes the buffers itself: the limit here only raises the kernel's limit in the sandbox, to twice this limit, and never lowers it.",
      behavior: "TCP behavior, timeouts and UDP",
      cubic: "Backs off little after a loss and recovers quickly; the default for long distances and high bandwidth",
      reno: "Halves the window after a loss and recovers linearly; more conservative",
      bbr: "Follows the rate actually delivered, so scattered losses do not make it back off; used only by connections with strict isolation when the kernel supports it, the others use Cubic",
      nagle: "Nagle's algorithm",
      nagleMeaning:
        "Gathers small pieces into full segments before sending: fewer packets, but interactive connections (SSH, games) wait a little longer. Off by default.",
      milliseconds: "ms",
      delayedAckHint:
        "An acknowledgement waits at most this long before it is sent; 0 acknowledges every segment at once",
      connectTimeoutHint: "Give up when the destination has not completed the handshake after this long",
      keepaliveInterval: "Keepalive interval",
      keepaliveHint: "An idle connection is probed this often",
      deadPeerHint: "End the connection when the other side has sent no answer at all for this long",
      udpBufferHint: "Per UDP association, per direction",
      ranges: {
        title: "Round-trip time ranges",
        label: "Round-trip time ranges (shortest first)",
        start: (n: number) => `Start of range ${n} (ms)`,
        /** Between a range's start (a number field) and the profile it uses (a select). */
        thenUse: "ms and up, use",
        profile: (n: number) => `Profile range ${n} uses`,
        choose: "Choose a profile…",
        remove: (n: number) => `Remove range ${n}`,
        lastOne: "There has to be at least one range",
        firstStays: "The first range starts at 0 ms and cannot be removed",
        atMost: (max: number) => `At most ${max} ranges`,
        add: "Add range",
      },
      healthOfAutomatic: "An automatic profile uses its own health probe; it does not change with the range.",
      /** The unit after the label of the consecutive failures field: a count has none in English. */
      failuresUnit: "",
      failuresHint: "At this many, new connections are no longer accepted",
      handshakeHint: "How long a start waits for the WireGuard handshake",
      saved: (name: string) => `Saved ${name}`,
      savedInUse: (name: string) =>
        `Saved ${name}: the connections that use it apply it at once to the connections they open from now on`,
      created: (name: string) => `Created ${name}`,
      errors: {
        wholeNumber: (min: number, max: number) => `Enter a whole number from ${min} to ${max}`,
        startAboveLimit: "The initial size cannot exceed the limit",
        deadPeerTooShort: "Must be at least twice the keepalive interval",
        rangeStart: (min: number, max: number) => `Enter a start from ${min} to ${max} ms`,
        firstRange: "The first range must start at 0 ms",
        rangeOrder: "The start must be greater than the previous range's",
        rangeProfile: "Choose the profile this range uses",
      },
    },
    actions: {
      copy: "Duplicate",
      copyBuiltIn: "Duplicate to my profiles",
      deleting: "“Delete” is being sent; wait until it is done",
      inUse: (count: number) =>
        count === 1
          ? "1 connection uses this profile: switch it to another transport profile first"
          : `${count} connections use this profile: switch them to another transport profile first`,
      namedBy: (names: readonly string[]) =>
        names.length === 1
          ? `A range of the automatic profile ${quotedEn(names)} uses it: switch that range to another profile first`
          : `Ranges of the automatic profiles ${quotedEn(names)} use it: switch those ranges to another profile first`,
      deleted: (name: string) => `Deleted transport profile ${name}`,
      /** What a failed deletion is reported as (the notification adds that it failed). */
      deleteIntent: (name: string) => `Delete ${name}`,
    },
    deleteConfirm: {
      title: (name: string) => `Delete the transport profile “${name}”?`,
      unused:
        "No connection uses this profile and no range of an automatic profile uses it, so no connection is affected.",
    },
    model: {
      /** In place of the name of a profile that no longer exists. */
      gone: "(no longer exists)",
      /** A buffer that opens at one size and may grow to another. */
      bufferRange: (start: string, limit: string) => `from ${start} up to ${limit}`,
      fixed: (send: string, receive: string) => `Fixed · send ${send} / receive ${receive}`,
      /** A fixed profile's buffers alone, under the range that uses it. */
      buffers: (send: string, receive: string) => `Send ${send} / receive ${receive}`,
      /** An automatic profile: the profiles of its ranges, shortest round trip first. */
      automatic: (names: readonly string[]) => `Automatic · ${names.join(" → ")}`,
      congestionUnconfirmed: (asked: string) =>
        `Congestion control: ${asked} requested; not confirmed yet, because the connection has not opened a TCP connection of its own`,
      congestionInEffect: (name: string) =>
        `Congestion control: ${name} in effect (only for the TCP connections the connection opens itself, not for those a strictly isolated app opens)`,
      congestionUserspace: (asked: string, inUse: string) =>
        `Congestion control: ${asked} requested, ${inUse} in use (the userspace TCP stack has no BBR; it takes strict isolation to use it)`,
      congestionKernel: (asked: string, inUse: string) =>
        `Congestion control: ${asked} requested, ${inUse} in use (the kernel does not offer it to unprivileged programs: the module is not loaded, or it is not in net.ipv4.tcp_allowed_congestion_control)`,
    },
  },
  "zh-TW": {
    title: "傳輸設定",
    description: "每條連線的緩衝、TCP 行為、逾時與健康探測；可以固定一組，或依往返時間自動切換。",
    help: "每條連線使用一份傳輸設定，沒有另外選擇時是「自動」。固定的設定是一組數值；自動的設定為每個往返時間區間選用一份固定的設定，連線量到的往返時間落在哪個區間，之後建立的連線就採用那一份。緩衝的上限決定單一連線的速度上限（緩衝 ÷ 往返時間）；連線以起始大小建立，傳得快時才放大，並且只用連線緩衝預算的四分之三，剩下的留給新連線。儲存後立即套用到之後建立的連線，不需要重新啟動；已經建立的連線維持原樣。嚴格隔離的連線由 Linux 核心自己調整緩衝，這裡的上限只會把核心的上限調高。",
    helpText: "儲存後立即套用到之後建立的連線，不需要重新啟動；已經建立的連線維持原樣。",
    add: "新增傳輸設定",
    newProfile: "新的傳輸設定",
    loading: "載入傳輸設定",
    notFound: "找不到這份傳輸設定",
    stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
    actionsOf: (name) => `${name} 的操作`,
    moreActionsOf: (name) => `${name} 的更多操作`,
    usedBy: (count) => (count ? `${count} 條連線使用` : "沒有連線使用"),
    list: {
      label: "傳輸設定清單",
      builtIn: "內建的傳輸設定",
      mine: "我的設定",
      mineLabel: "我的傳輸設定",
      noneOfMine: "還沒有自訂的設定。打開一份內建設定，按「複製成我的設定」就能從它開始調整。",
      all: "所有傳輸設定",
      detail: "傳輸設定",
      settingsOf: (name) => `${name} 的設定`,
      meta: (brief, users) => `${brief}${users ? ` · ${users} 條連線` : ""}`,
    },
    users: {
      title: "使用中的連線",
      label: "使用這份傳輸設定的連線",
      range: (name) => `目前「${name}」`,
      none: "沒有連線使用這份設定；在連線的設定中選用後才會生效。",
    },
    values: {
      byRoundTrip: "依往返時間選用",
      measuring:
        "連線每建立一條 TCP 連線就量一次往返時間（握手花的時間），取最近幾次的中位數。之後新建立的連線採用所在區間的設定；已經建立的連線不受影響。",
      fromRoundTrip: (ms) => `${ms} 毫秒起`,
      tcpBuffers: "TCP 緩衝",
      send: "送出",
      receive: "接收",
      ceiling: (roundTripMs, upload, download) =>
        `往返 ${roundTripMs} 毫秒時，單一連線上傳最多約 ${upload} MB/s、下載約 ${download} MB/s（緩衝 ÷ 往返時間）。`,
      tcpBehavior: "TCP 行為與逾時",
      congestion: "壅塞控制",
      on: "開啟",
      off: "關閉",
      delayedAck: "延遲 ACK",
      connectTimeout: "連線逾時",
      keepalive: "keepalive",
      every: (secs) => `每 ${secs} 秒`,
      deadPeer: "無回應中止",
      udpBuffer: "UDP 緩衝",
      perDirection: "每個方向",
      health: "健康探測",
      probeInterval: "探測間隔",
      failures: "連續失敗",
      failuresMeaning: "達到這個次數就停止接受新連線，直到探測恢復",
      failureCount: (count) => `${count} 次`,
      handshakeTimeout: "握手逾時",
      handshakeMeaning: "啟動時等待第一次 WireGuard 握手的時間",
      secs: (secs) => `${secs} 秒`,
      ms: (ms) => `${ms} 毫秒`,
    },
    builtIn: {
      note: "內建設定是程式的一部分，不能修改；複製一份就能調整每個數值。",
    },
    editor: {
      duplicating: (name) => `複製「${name}」`,
      copyName: (name) => `${name} 的副本`,
      description: "每條連線的緩衝、TCP 行為、逾時，以及連線健康探測的方式。",
      idLabel: "傳輸設定 ID",
      appliesAtOnce: "儲存後立即套用：使用它的連線之後建立的連線採用新值，不需要重新啟動。",
      unused: "還沒有連線使用；在連線的設定中選用。",
      afterCreating: "建立後可以在連線的設定中選用。",
      namePlaceholder: "例如：雙層 VPN 上傳",
      kind: "設定的類型",
      fixed: "固定",
      fixedTitle: "一組固定的數值",
      fixedNote: "一組固定的數值，不論量到什麼都使用它。",
      automatic: "自動",
      automaticTitle: "依量到的往返時間，選用不同的固定設定",
      automaticNote: "依量到的往返時間，為每個區間選用一份固定的設定。",
      mustStayFixed: (names) => `自動設定${quotedCjk(names)}的區間選用了這份設定：它必須維持固定，儲存會被拒絕。`,
      buffers:
        "緩衝決定單一連線的速度上限。連線以起始大小建立（這是它一建立就佔用的連線緩衝），傳得夠快時才一次加倍、放大到上限；用不到的連線維持起始大小。",
      sendStart: "送出：起始",
      sendLimit: "送出：上限",
      uploadDirection: "上傳方向",
      receiveStart: "接收：起始",
      receiveLimit: "接收：上限",
      downloadDirection: "下載方向",
      strictIsolation:
        "嚴格隔離的連線由 Linux 核心自己調整緩衝大小：這裡的上限只會把沙箱裡核心的上限調高到它的兩倍，從不調低。",
      behavior: "TCP 行為、逾時與 UDP",
      cubic: "掉包後退得少、恢復快；長距離與高頻寬的預設",
      reno: "掉包後視窗減半、線性恢復；較保守",
      bbr: "依實際送達的速率調整，零星掉包不會讓它退讓；只有嚴格隔離的連線在核心支援時使用，其餘用 Cubic",
      nagle: "Nagle 演算法",
      nagleMeaning: "把零碎的小封包併成整段再送：省封包，但互動式連線（SSH、遊戲）會多等一下。預設關閉。",
      milliseconds: "毫秒",
      delayedAckHint: "確認封包最多等這麼久再送；0 表示每段都立即確認",
      connectTimeoutHint: "目的地這麼久沒有完成握手就放棄",
      keepaliveInterval: "keepalive 間隔",
      keepaliveHint: "閒置的連線每隔這麼久探測一次",
      deadPeerHint: "對方這麼久沒有任何回應就結束連線",
      udpBufferHint: "每個 UDP 關聯、每個方向",
      ranges: {
        title: "往返時間區間",
        label: "往返時間區間（由小到大）",
        start: (n) => `第 ${n} 個區間的起點（毫秒）`,
        thenUse: "毫秒起，使用",
        profile: (n) => `第 ${n} 個區間使用的設定`,
        choose: "選擇設定…",
        remove: (n) => `移除第 ${n} 個區間`,
        lastOne: "至少要有一個區間",
        firstStays: "第一個區間從 0 毫秒開始，不能移除",
        atMost: (max) => `最多 ${max} 個區間`,
        add: "新增區間",
      },
      healthOfAutomatic: "自動設定用它自己的健康探測，不隨區間切換。",
      failuresUnit: "次",
      failuresHint: "達到後停止接受新連線",
      handshakeHint: "啟動時等待 WireGuard 握手",
      saved: (name) => `已儲存 ${name}`,
      savedInUse: (name) => `已儲存 ${name}：使用它的連線之後建立的連線立即採用`,
      created: (name) => `已建立 ${name}`,
      errors: {
        wholeNumber: (min, max) => `請輸入 ${min}–${max} 的整數`,
        startAboveLimit: "起始大小不能超過上限",
        deadPeerTooShort: "至少要是 keepalive 間隔的兩倍",
        rangeStart: (min, max) => `起點請輸入 ${min}–${max} 毫秒`,
        firstRange: "第一個區間必須從 0 毫秒開始",
        rangeOrder: "起點必須大於前一個區間",
        rangeProfile: "請選擇這個區間使用的設定",
      },
    },
    actions: {
      copy: "複製",
      copyBuiltIn: "複製成我的設定",
      deleting: "正在送出「刪除」，完成後再操作",
      inUse: (count) => `${count} 條連線使用這份設定：先讓它們改用其他傳輸設定`,
      namedBy: (names) => `自動設定${quotedCjk(names)}的區間選用了它：先讓那些區間改用其他設定`,
      deleted: (name) => `已刪除傳輸設定 ${name}`,
      deleteIntent: (name) => `刪除 ${name}`,
    },
    deleteConfirm: {
      title: (name) => `刪除傳輸設定「${name}」？`,
      unused: "沒有連線使用這份設定，也沒有自動設定的區間選用它，所以不影響任何連線。",
    },
    model: {
      gone: "（已不存在）",
      bufferRange: (start, limit) => `${start} 起，最多 ${limit}`,
      fixed: (send, receive) => `固定 · 送 ${send}／收 ${receive}`,
      buffers: (send, receive) => `送 ${send}／收 ${receive}`,
      // The profiles' own names hold a "／": the ranges are told apart by an arrow.
      automatic: (names) => `自動 · ${names.join(" → ")}`,
      congestionUnconfirmed: (asked) => `壅塞控制：要求 ${asked}，連線還沒有開過自己的 TCP 連線，尚未確認`,
      congestionInEffect: (name) =>
        `壅塞控制：${name} 已生效（只及於連線自己開的 TCP 連線，嚴格隔離 App 自己開的不在內）`,
      congestionUserspace: (asked, inUse) =>
        `壅塞控制：要求 ${asked}，實際是 ${inUse}（使用者態 TCP 沒有 BBR，開啟嚴格隔離才用得到）`,
      congestionKernel: (asked, inUse) =>
        `壅塞控制：要求 ${asked}，實際是 ${inUse}（核心沒有給非特權程式用：模組沒載入，或不在 net.ipv4.tcp_allowed_congestion_control 裡）`,
    },
  },
  ja: {
    title: "トランスポート設定",
    description:
      "接続ごとのバッファー、TCP の動作、タイムアウト、ヘルスチェック。固定の 1 組にするか、往復時間に応じて自動で切り替えます。",
    help: "接続ごとにトランスポート設定を 1 つ使います。ほかに選ばなければ「自動」です。固定の設定は値の 1 組です。自動の設定は往復時間の区間ごとに固定の設定を 1 つ選び、接続が測った往復時間が入る区間の設定が、その後に確立する接続に使われます。バッファーの上限は 1 本の接続の速度上限を決めます（バッファー ÷ 往復時間）。接続は初期サイズで確立され、速く転送しているときだけ拡大します。拡大に使うのは接続バッファー予算の 4 分の 3 までで、残りは新しい接続のために残します。保存すると、その後に確立する接続にすぐ適用され、再起動は不要です。すでに確立した接続はそのままです。厳格な分離の接続では Linux カーネルが自分でバッファーを調整し、ここでの上限はカーネルの上限を引き上げるだけです。",
    helpText: "保存すると、その後に確立する接続にすぐ適用され、再起動は不要です。すでに確立した接続はそのままです。",
    add: "トランスポート設定を追加",
    newProfile: "新しいトランスポート設定",
    loading: "トランスポート設定を読み込み中",
    notFound: "このトランスポート設定が見つかりません",
    stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
    actionsOf: (name) => `${name} の操作`,
    moreActionsOf: (name) => `${name} のその他の操作`,
    usedBy: (count) => (count ? `${count} 件の接続が使用中` : "使用中の接続なし"),
    list: {
      label: "トランスポート設定の一覧",
      builtIn: "組み込みのトランスポート設定",
      mine: "自分の設定",
      mineLabel: "自分のトランスポート設定",
      noneOfMine:
        "自分の設定はまだありません。組み込み設定を開いて「自分の設定として複製」を押すと、そこから調整を始められます。",
      all: "すべてのトランスポート設定",
      detail: "トランスポート設定",
      settingsOf: (name) => `${name} の設定`,
      meta: (brief, users) => `${brief}${users ? ` · ${users} 件の接続` : ""}`,
    },
    users: {
      title: "使用中の接続",
      label: "このトランスポート設定を使用している接続",
      range: (name) => `現在「${name}」`,
      none: "この設定を使用している接続はありません。接続の設定で選ぶと有効になります。",
    },
    values: {
      byRoundTrip: "往復時間による選択",
      measuring:
        "接続は TCP 接続を確立するたびに往復時間（ハンドシェイクにかかった時間）を測り、直近数回の中央値を採ります。その後に確立する接続には、その値が入る区間の設定が使われます。すでに確立した接続には影響しません。",
      fromRoundTrip: (ms) => `${ms} ミリ秒から`,
      tcpBuffers: "TCP バッファー",
      send: "送信",
      receive: "受信",
      ceiling: (roundTripMs, upload, download) =>
        `往復 ${roundTripMs} ミリ秒のとき、1 本の接続でアップロードは最大約 ${upload} MB/s、ダウンロードは約 ${download} MB/s です（バッファー ÷ 往復時間）。`,
      tcpBehavior: "TCP の動作とタイムアウト",
      congestion: "輻輳制御",
      on: "オン",
      off: "オフ",
      delayedAck: "遅延 ACK",
      connectTimeout: "接続タイムアウト",
      keepalive: "キープアライブ",
      every: (secs) => `${secs} 秒ごと`,
      deadPeer: "無応答タイムアウト",
      udpBuffer: "UDP バッファー",
      perDirection: "方向ごと",
      health: "ヘルスチェック",
      probeInterval: "チェック間隔",
      failures: "連続失敗",
      failuresMeaning: "この回数に達すると、チェックが回復するまで新しい接続を受け付けません",
      failureCount: (count) => `${count} 回`,
      handshakeTimeout: "ハンドシェイクのタイムアウト",
      handshakeMeaning: "開始時に最初の WireGuard ハンドシェイクを待つ時間",
      secs: (secs) => `${secs} 秒`,
      ms: (ms) => `${ms} ミリ秒`,
    },
    builtIn: {
      note: "組み込み設定はプログラムの一部で、変更できません。複製すると、すべての値を調整できます。",
    },
    editor: {
      duplicating: (name) => `「${name}」を複製`,
      copyName: (name) => `${name} のコピー`,
      description: "接続ごとのバッファー、TCP の動作、タイムアウトと、接続のヘルスチェックの方法。",
      idLabel: "トランスポート設定 ID",
      appliesAtOnce:
        "保存するとすぐに適用されます。使用している接続では、その後に確立する接続に新しい値が使われ、再起動は不要です。",
      unused: "まだ使用している接続はありません。接続の設定で選んでください。",
      afterCreating: "作成後、接続の設定で選べます。",
      namePlaceholder: "例：二重 VPN アップロード",
      kind: "設定の種類",
      fixed: "固定",
      fixedTitle: "固定の値の 1 組",
      fixedNote: "固定の値の 1 組です。測定結果にかかわらず使われます。",
      automatic: "自動",
      automaticTitle: "測定した往復時間に応じて、異なる固定設定を選びます",
      automaticNote: "測定した往復時間に応じて、区間ごとに固定設定を 1 つ選びます。",
      mustStayFixed: (names) =>
        `自動設定${quotedCjk(names)}の区間がこの設定を使用しています。固定のままにする必要があり、保存は拒否されます。`,
      buffers:
        "バッファーは 1 本の接続の速度上限を決めます。接続は初期サイズで確立され（確立した時点で占有する接続バッファーです）、十分に速く転送しているときだけ 1 回ごとに倍にして上限まで拡大します。必要としない接続は初期サイズのままです。",
      sendStart: "送信：初期",
      sendLimit: "送信：上限",
      uploadDirection: "アップロード方向",
      receiveStart: "受信：初期",
      receiveLimit: "受信：上限",
      downloadDirection: "ダウンロード方向",
      strictIsolation:
        "厳格な分離の接続では Linux カーネルがバッファーの大きさを自分で調整します。ここでの上限は、サンドボックス内のカーネルの上限をその 2 倍まで引き上げるだけで、引き下げることはありません。",
      behavior: "TCP の動作、タイムアウト、UDP",
      cubic: "パケットロス後の後退が小さく、回復が速い。長距離・広帯域での既定",
      reno: "パケットロス後にウィンドウを半分にし、線形に回復する。より保守的",
      bbr: "実際に届いた速度に合わせて調整し、散発的なパケットロスでは後退しない。厳格な分離の接続だけが、カーネルが対応している場合に使い、それ以外は Cubic を使う",
      nagle: "Nagle アルゴリズム",
      nagleMeaning:
        "細かい小さなパケットをまとめてから送ります。パケット数は減りますが、対話的な接続（SSH、ゲーム）は少し待たされます。既定ではオフです。",
      milliseconds: "ミリ秒",
      delayedAckHint: "確認応答は最大でこの時間待ってから送ります。0 にするとセグメントごとにすぐ確認します",
      connectTimeoutHint: "宛先がこの時間内にハンドシェイクを完了しなければ諦めます",
      keepaliveInterval: "キープアライブ間隔",
      keepaliveHint: "アイドル状態の接続をこの間隔で確認します",
      deadPeerHint: "相手からこの時間まったく応答がなければ接続を終了します",
      udpBufferHint: "UDP アソシエーションごと、方向ごと",
      ranges: {
        title: "往復時間の区間",
        label: "往復時間の区間（小さい順）",
        start: (n) => `${n} 番目の区間の開始点（ミリ秒）`,
        thenUse: "ミリ秒以上で使用",
        profile: (n) => `${n} 番目の区間で使う設定`,
        choose: "設定を選択…",
        remove: (n) => `${n} 番目の区間を削除`,
        lastOne: "区間は 1 つ以上必要です",
        firstStays: "最初の区間は 0 ミリ秒から始まるため、削除できません",
        atMost: (max) => `区間は最大 ${max} 個です`,
        add: "区間を追加",
      },
      healthOfAutomatic: "自動設定は自身のヘルスチェックを使い、区間によって切り替わりません。",
      failuresUnit: "回",
      failuresHint: "達すると新しい接続を受け付けません",
      handshakeHint: "開始時に WireGuard ハンドシェイクを待つ時間",
      saved: (name) => `${name} を保存しました`,
      savedInUse: (name) => `${name} を保存しました。使用している接続では、今後確立する接続にすぐ適用されます`,
      created: (name) => `${name} を作成しました`,
      errors: {
        wholeNumber: (min, max) => `${min}–${max} の整数を入力してください`,
        startAboveLimit: "初期サイズは上限を超えられません",
        deadPeerTooShort: "キープアライブ間隔の 2 倍以上にしてください",
        rangeStart: (min, max) => `開始点は ${min}–${max} ミリ秒で入力してください`,
        firstRange: "最初の区間は 0 ミリ秒から始める必要があります",
        rangeOrder: "開始点は前の区間より大きくしてください",
        rangeProfile: "この区間で使う設定を選んでください",
      },
    },
    actions: {
      copy: "複製",
      copyBuiltIn: "自分の設定として複製",
      deleting: "「削除」を送信中です。完了してから操作してください",
      inUse: (count) => `${count} 件の接続がこの設定を使用しています。先に別のトランスポート設定に切り替えてください`,
      namedBy: (names) =>
        `自動設定${quotedCjk(names)}の区間がこの設定を使用しています。先にそれらの区間を別の設定に切り替えてください`,
      deleted: (name) => `トランスポート設定 ${name} を削除しました`,
      deleteIntent: (name) => `${name} の削除`,
    },
    deleteConfirm: {
      title: (name) => `トランスポート設定「${name}」を削除しますか？`,
      unused: "この設定を使用している接続はなく、自動設定の区間でも使われていないため、どの接続にも影響しません。",
    },
    model: {
      gone: "（存在しません）",
      bufferRange: (start, limit) => `${start} から最大 ${limit}`,
      fixed: (send, receive) => `固定 · 送信 ${send}／受信 ${receive}`,
      buffers: (send, receive) => `送信 ${send}／受信 ${receive}`,
      automatic: (names) => `自動 · ${names.join(" → ")}`,
      congestionUnconfirmed: (asked) =>
        `輻輳制御：${asked} を要求。接続がまだ自身の TCP 接続を開いていないため、未確認です`,
      congestionInEffect: (name) =>
        `輻輳制御：${name} が有効（接続自身が開く TCP 接続のみ。厳格な分離のアプリが自分で開くものは対象外）`,
      congestionUserspace: (asked, inUse) =>
        `輻輳制御：${asked} を要求、実際は ${inUse}（ユーザー空間の TCP には BBR がなく、厳格な分離を有効にすると使えます）`,
      congestionKernel: (asked, inUse) =>
        `輻輳制御：${asked} を要求、実際は ${inUse}（カーネルが非特権プログラムに許可していません。モジュールが読み込まれていないか、net.ipv4.tcp_allowed_congestion_control に含まれていません）`,
    },
  },
});
