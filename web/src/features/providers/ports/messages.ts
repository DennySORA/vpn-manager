// Text of AirVPN's forwarded ports (連入埠, "inbound ports"), which VPN Manager manages on AirVPN's website through the
// Provider egress: the account page's section (the list, reserving, the free-port search and the DDNS check), a port's
// actions, its settings and test dialogs, the picker of the port forward dialog, and the lines `ports.ts` writes.
// AirVPN's own option names (Ports, Client Area, Local port) and its answers are shown as they are.

import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** “A”, “B”, and “C”. */
function quotedEn(names: readonly string[]): string {
  return listEn.format(names.map((name) => `“${name}”`));
}

export const m = defineMessages({
  en: {
    title: "Inbound ports",
    /** A port by number, inside a sentence or an accessible name. */
    named: (port: number) => `inbound port ${port}`,
    protocol: { both: "TCP + UDP", tcpOnly: "TCP only", udpOnly: "UDP only" },
    ipLayer: { both: "IPv4 + IPv6", ipv4Only: "IPv4 only", ipv6Only: "IPv6 only" },
    /** A port forwarded to every device of the account. */
    allDevices: "All devices",
    /** A device the list does not name: the start of its ID. */
    deviceById: (id: string) => `Device ${id}…`,
    usage: (used: number, limit: number) => `${used} of ${limit} used`,
    enabled: "Enabled",
    /** A test session's server when AirVPN named none. */
    serverUnknown: "AirVPN server",
    retry: "Retry",
    /** A range of whole numbers to type. */
    enterRange: (min: number, max: number) => `Enter ${min}–${max}`,
    reserve: {
      label: "Reserve an inbound port",
      port: "Port to reserve",
      byAirvpn: "Picked by AirVPN",
      chosen: "Specify",
      submit: "Reserve a port",
      reserving: "Reserving",
      /** The field of the port number to ask for. */
      portField: "Port",
      limitReached: (limit: number) => `At most ${limit} per account: delete a port that is no longer used first`,
      /** The same, said where the ports cannot be deleted (the port forward dialog). */
      limitReachedElsewhere: (limit: number) =>
        `At most ${limit} per account: delete a port that is no longer used on the Providers page first`,
      range: (min: number) => `Enter ${min}–65535 (AirVPN does not accept a smaller port)`,
      taken: (port: number) => `This account has already reserved ${port}`,
      allUsed: (limit: number) =>
        `All ${limit} are in use: delete a port that is no longer used before reserving another.`,
      hint: (limit: number, min: number) =>
        `At most ${limit} per account, ${min} or above; the same set on every AirVPN server. AirVPN releases them 10 days after the premium plan expires.`,
      reserved: (port: number) => `Reserved inbound port ${port}`,
      reservedDetail: "Choose “Create port forward” in its ⋯ menu to forward it to a managed app of this connection.",
      /** Reserved from the port forward dialog. */
      reservedFilled: "AirVPN reserved the port, and it is filled in the form.",
    },
    /** AirVPN's search for consecutive ports nobody holds; it reserves nothing. */
    search: {
      label: "Find consecutive free ports",
      count: "Number of consecutive free ports",
      searching: "Searching",
      failed: "The search did not complete",
      result: (count: number) => `AirVPN (looking for ${count} consecutive free ports)`,
      hint: "This only looks; nothing is reserved. To reserve one of them, choose “Specify” above and enter that port.",
    },
    /** AirVPN's DDNS check: where each DDNS name of the account's ports leads now. */
    ddns: {
      intro:
        "DDNS check: AirVPN reports how many connections each DDNS name points to, and the addresses it should resolve to.",
      check: "Check DDNS",
      failed: "The DDNS check did not complete",
      none: "AirVPN reported no DDNS name: add one under “Settings” in a port's ⋯ menu, then check again.",
      names: "DDNS names",
      resolvesTo: (addresses: readonly string[]) => `Should resolve to ${addresses.join(", ")}`,
      unused: "No connection uses its port: the name points nowhere right now",
      one: "Points to 1 connection",
      /** `count` is 2 or more. */
      many: (count: number) =>
        `${count} connections use its port: the name has several destinations and may not lead to the one you want`,
    },
    list: {
      needEgress: "Reading the inbound ports through AirVPN's website needs a usable Provider egress.",
      unreadable: "Cannot read the inbound ports through AirVPN's website",
      manageOnWebsite: "You can also manage them on AirVPN's website directly:",
      reserveOnWebsite: "You can also reserve one yourself on AirVPN's website:",
      loading: "Signing in to AirVPN's website through the Provider egress to read the inbound ports",
      /** After how many ports are used: when the list was read. */
      readAt: (time: string) => `read at ${time}; P2P programs must listen on the same port.`,
      none: "This account has no inbound ports reserved yet",
      noneYet: "This account has no inbound ports reserved yet.",
      noneHint: "Reserve a port so that the outside can reach this account's connections through AirVPN.",
      refresh: "Refresh inbound ports",
      noConnection: "Create a connection from this account first, so that the port forward has somewhere to arrive",
      notes: (text: string) => `Notes: ${text}`,
      forwards: (names: readonly string[]) => `Port forwards: ${names.join(", ")}`,
    },
    /** The account's ports in the port forward dialog. */
    picker: {
      title: (account: string) => `AirVPN inbound ports (account “${account}”)`,
      choose: "Choose an inbound port",
      disabledOnWebsite: "This port is disabled on AirVPN's website",
      /** `usage`: how many ports are used. */
      hint: (usage: string) =>
        `${usage} (the same on every AirVPN server). Picking a port fills in the tunnel port, the public port and the app's port.`,
    },
    remove: {
      title: (port: number | string) => `Delete inbound port ${port}?`,
      confirm: "Delete inbound port",
      body: "AirVPN releases the port at once, and the same port may not be available to reserve again; the account's other inbound ports are not affected.",
      usedBy: (names: readonly string[]) =>
        names.length === 1
          ? `The port forward ${quotedEn(names)} uses this port: once it is deleted, nothing from outside gets through; the port forward itself is not deleted.`
          : `The port forwards ${quotedEn(names)} use this port: once it is deleted, nothing from outside gets through; the port forwards themselves are not deleted.`,
      deleted: (port: number) => `Deleted inbound port ${port}`,
      deletedDetail: "AirVPN released the port.",
      /** What a failed deletion is reported as (the notification adds that it failed). */
      intent: (port: number) => `Delete inbound port ${port}`,
    },
    actions: {
      test: "Test",
      testing: "Testing",
      testBusy: (port: number) => `Inbound port ${port} is being tested; test again once it is done`,
      forward: "Create port forward",
      settings: "Settings",
    },
    settings: {
      title: "Inbound port settings",
      gone: "This inbound port is no longer in the account",
      goneHint: "It may have been deleted elsewhere; read the inbound port list again to confirm.",
      titleOf: (port: number) => `Settings of inbound port ${port}`,
      description:
        "The same as the Ports page in the Client Area of AirVPN's website: each setting is sent on its own and read back after saving to confirm it. Every AirVPN server uses these settings.",
      enable: "Enable this port",
      enableHint: "Once it is disabled, AirVPN no longer forwards it; the reservation stays.",
      /** The settings by name (the dialog's fields, and the list of what a save changes). */
      fields: {
        notes: "Notes",
        enabled: "Enabled",
        device: "Device",
        protocol: "Protocol",
        ipVersion: "IP version",
        ddnsName: "DDNS name",
      },
      /** The port has an IP layer word of AirVPN's own. */
      layerAsIs: (layer: string) => `AirVPN has “${layer}” now; it changes only when you pick one.`,
      deviceHint: "Forward only to this device's connections, or to every device of the account",
      unlistedDevice: (id: string) => `Device ${id}… (not in the list)`,
      localPortHint: (port: number) =>
        `Connections from outside to ${port} are delivered to this port at the tunnel address`,
      ddnsHint: (suffix: string, max: number) =>
        `The full name is “name${suffix}”: letters, digits and hyphens, at most ${max} characters; leave it empty to clear it`,
      notesHint: (max: number) =>
        `Only you can see it, on AirVPN's website; at most ${max} characters; leave it empty to clear it`,
      fixFirst: "Fix the marked fields first.",
      unchanged: "No setting has been changed yet.",
      willChange: (names: readonly string[]) =>
        `Will change: ${names.join(", ")} (one request each, then read back to confirm).`,
      saved: (port: number) => `Saved the settings of inbound port ${port}`,
      /** `readBack`: the changed settings as AirVPN holds them now. */
      savedDetail: (readBack: string) => `AirVPN read back: ${readBack}.`,
      errors: {
        notesOneLine: "Notes must be a single line",
        notesTooLong: (max: number) => `Notes have at most ${max} characters`,
        ddnsChars: "Only letters, digits and hyphens, with no hyphen at the start or the end",
        ddnsTooLong: (max: number) => `At most ${max} characters`,
      },
      /** Each changed setting as AirVPN read it back. */
      readBack: {
        notes: (text: string) => `Notes “${text}”`,
        noNotes: "No notes",
        device: (label: string) => `Device: ${label}`,
        protocol: (protocol: string) => `Protocol ${protocol}`,
        ipVersion: (layer: string) => `IP version ${layer}`,
        noDdns: "No DDNS name",
        list: (parts: readonly string[]) => parts.join("; "),
      },
    },
    /** Why the app must listen on the forwarded port itself. */
    sameLocalPort: (port: number) =>
      `The app must listen on ${port}: AirVPN delivers connections from outside to ${port} unchanged to this connection's tunnel port ${port}, and P2P programs (BitTorrent, for example) announce ${port} too. Do not let the app use another port, and do not change this inbound port's Local port to another port.`,
    /** AirVPN remaps the port to another local port. */
    remapped: (port: number, local: number) =>
      `AirVPN maps ${port} to local port ${local}: a P2P program has to listen on the same port the outside sees, so change Local port back to ${port} in the inbound port's “Settings”.`,
    /** A Local port typed that is not the public port. */
    localPortDiffers: (port: number, local: string) =>
      `VPN Manager's port forwards and P2P programs need it to be the public port: connections from outside to ${port} would arrive at ${local} on the tunnel, while the app has to listen on ${port}, and P2P programs announce ${port} too.`,
    /** Doing it on AirVPN's website by hand. */
    websiteSteps: [
      "Sign in to the Client Area of AirVPN's website in a browser and open “Ports”.",
      "Reserve a port (at most 5 per account, 2049 or above) and choose TCP, UDP or both; leave Local port empty.",
      "Come back here and create the port forward: enter the same port as the tunnel port, the public port and the app's port.",
    ],
    /** AirVPN's test of a port, from the server of every connected session that uses it. */
    test: {
      title: (port: number | string) => `Test inbound port ${port}`,
      description:
        "AirVPN connects to this port from the server of every connection that uses it, the same as the test on AirVPN's website.",
      again: "Test again",
      running: (port: number) =>
        `AirVPN is connecting to ${port} from its servers: about 15 seconds at most per connection.`,
      failed: "The test did not complete",
      results: "Test results by connection",
      outside: "The outside connects to this server address",
      /** Read between the server address and the connection's address, where an arrow is drawn. */
      deliveredTo: "delivered to",
      delivered: "The address AirVPN delivers to on this connection",
      device: (name: string) => `(device ${name})`,
      said: (message: string) => `AirVPN: ${message}`,
      testedAt: (time: string) => `Tested at ${time}; AirVPN tests TCP only, so UDP connections have no result.`,
      portDisabled: "This port is disabled",
      portDisabledHint: "AirVPN does not forward a disabled port: enable it in “Settings” first, then test.",
      noSession: "No AirVPN connection uses this port right now, so there is nothing to test",
      steps: {
        /** `device`: the one device the port is limited to, if any. */
        connect: (device: string | null) =>
          `Create and start a connection from this account (“Create connection” above)${device ? `; this port is forwarded only to the device “${device}”, so use that device` : ""}.`,
        listen: (port: number) =>
          `Make a program listen on ${port}: press “Create port forward” to forward it to a managed app of this connection, or let the app listen by itself.`,
        again: "Test again.",
      },
      /** What AirVPN's test of one session said. */
      state: {
        open: "Reachable",
        closed: "Not reachable",
        warning: "Warning",
        unknown: "Result unclear",
        /** `word`: AirVPN's own word for the result. */
        unknownSaid: (word: string) => `Result unclear (AirVPN: ${word})`,
        not_tested: "Not tested",
      },
    },
  },
  "zh-TW": {
    title: "連入埠",
    named: (port) => `連入埠 ${port}`,
    protocol: { both: "TCP＋UDP", tcpOnly: "只有 TCP", udpOnly: "只有 UDP" },
    ipLayer: { both: "IPv4＋IPv6", ipv4Only: "只有 IPv4", ipv6Only: "只有 IPv6" },
    allDevices: "全部裝置",
    deviceById: (id) => `裝置 ${id}…`,
    usage: (used, limit) => `已用 ${used}／${limit} 個`,
    enabled: "已啟用",
    serverUnknown: "AirVPN 伺服器",
    retry: "重試",
    enterRange: (min, max) => `請輸入 ${min}–${max}`,
    reserve: {
      label: "保留連入埠",
      port: "要保留的 port",
      byAirvpn: "由 AirVPN 挑選",
      chosen: "指定",
      submit: "保留一個埠",
      reserving: "保留中",
      portField: "port",
      limitReached: (limit) => `每個帳號最多 ${limit} 個：先刪除不再使用的埠`,
      limitReachedElsewhere: (limit) => `每個帳號最多 ${limit} 個：先在供應商頁刪除不再使用的埠`,
      range: (min) => `請輸入 ${min}–65535（AirVPN 不接受更小的 port）`,
      taken: (port) => `這個帳號已經保留了 ${port}`,
      allUsed: (limit) => `已用完 ${limit} 個：先刪除不再使用的埠才能再保留。`,
      hint: (limit, min) =>
        `每個帳號最多 ${limit} 個、${min} 以上；所有 AirVPN 伺服器都是同一組。premium 方案到期 10 天後 AirVPN 會釋出它們。`,
      reserved: (port) => `已保留連入埠 ${port}`,
      reservedDetail: "從它的 ⋯ 選「建立轉發」，把它轉到這條連線的受管 App。",
      reservedFilled: "AirVPN 已保留這個埠，已填入表單。",
    },
    search: {
      label: "找連續的空閒埠",
      count: "連續空閒埠的數量",
      searching: "搜尋中",
      failed: "沒有完成搜尋",
      result: (count) => `AirVPN（找 ${count} 個連續的空閒埠）`,
      hint: "只是查詢，不會保留；要保留其中一個，在上方選「指定」並輸入那個 port。",
    },
    ddns: {
      intro: "DDNS 檢查：AirVPN 回報每個 DDNS 名稱指向幾條連線，以及它應該解析到的位址。",
      check: "檢查 DDNS",
      failed: "沒有完成 DDNS 檢查",
      none: "AirVPN 沒有回報任何 DDNS 名稱：從埠的 ⋯ 選「設定」加上 DDNS 名稱後再檢查。",
      names: "DDNS 名稱",
      resolvesTo: (addresses) => `應解析到 ${addresses.join("、")}`,
      unused: "沒有連線使用它的埠：名稱目前不指向任何地方",
      one: "指向 1 條連線",
      many: (count) => `有 ${count} 條連線使用它的埠：名稱有多個目的地，不一定連到你要的那條`,
    },
    list: {
      needEgress: "需要可用的 Provider 出口才能經 AirVPN 網站讀取連入埠。",
      unreadable: "無法經 AirVPN 網站讀取連入埠",
      manageOnWebsite: "也可以直接在 AirVPN 網站管理：",
      reserveOnWebsite: "也可以自己在 AirVPN 網站保留：",
      loading: "正在經 Provider 出口登入 AirVPN 網站讀取連入埠",
      readAt: (time) => `讀取於 ${time}；P2P 程式必須在同一個 port 監聽。`,
      none: "這個帳號還沒有保留連入埠",
      noneYet: "這個帳號還沒有保留連入埠。",
      noneHint: "保留一個埠，外部才能經 AirVPN 連進這個帳號的連線。",
      refresh: "重新讀取連入埠",
      noConnection: "先用這個帳號建立一條連線，轉發才有地方接收",
      notes: (text) => `備註：${text}`,
      forwards: (names) => `轉發：${names.join("、")}`,
    },
    picker: {
      title: (account) => `AirVPN 連入埠（帳號「${account}」）`,
      choose: "選擇連入埠",
      disabledOnWebsite: "這個埠在 AirVPN 網站被停用了",
      hint: (usage) => `${usage}（所有 AirVPN 伺服器相同）。選一個埠會填入 tunnel port、公開 port 與 App 的 port。`,
    },
    remove: {
      title: (port) => `刪除連入埠 ${port}？`,
      confirm: "刪除連入埠",
      body: "AirVPN 會立即釋出這個埠，之後不一定能再保留到同一個 port；這個帳號的其他連入埠不受影響。",
      usedBy: (names) => `轉發「${names.join("」「")}」使用這個埠：刪除後外部連不進來，轉發本身不會被刪除。`,
      deleted: (port) => `已刪除連入埠 ${port}`,
      deletedDetail: "AirVPN 已釋出這個埠。",
      intent: (port) => `刪除連入埠 ${port}`,
    },
    actions: {
      test: "測試",
      testing: "測試中",
      testBusy: (port) => `正在測試連入埠 ${port}，完成後再測試`,
      forward: "建立轉發",
      settings: "設定",
    },
    settings: {
      title: "連入埠的設定",
      gone: "這個連入埠已不在帳號中",
      goneHint: "它可能已在別處刪除；重新讀取連入埠清單確認。",
      titleOf: (port) => `連入埠 ${port} 的設定`,
      description:
        "和 AirVPN 網站 Client Area 的 Ports 頁相同：每項設定各自送出，儲存後重新讀取確認。所有 AirVPN 伺服器都用這組設定。",
      enable: "啟用這個埠",
      enableHint: "停用後 AirVPN 不再轉送它，保留仍在。",
      fields: {
        notes: "備註",
        enabled: "啟用狀態",
        device: "裝置",
        protocol: "協定",
        ipVersion: "IP 版本",
        ddnsName: "DDNS 名稱",
      },
      layerAsIs: (layer) => `AirVPN 目前是「${layer}」；選一個才會修改。`,
      deviceHint: "只轉給這台裝置的連線，或帳號的全部裝置",
      unlistedDevice: (id) => `裝置 ${id}…（不在清單中）`,
      localPortHint: (port) => `外部連到 ${port} 的連線送到 tunnel 位址的這個 port`,
      ddnsHint: (suffix, max) => `完整的名稱是「名稱${suffix}」：英文字母、數字與連字號，最多 ${max} 個字；留空會清除`,
      notesHint: (max) => `只有你在 AirVPN 網站看得到，最多 ${max} 個字；留空會清除`,
      fixFirst: "請先修正標示的欄位。",
      unchanged: "還沒有修改任何設定。",
      willChange: (names) => `會修改：${names.join("、")}（每項一個請求，之後重新讀取確認）。`,
      saved: (port) => `已儲存連入埠 ${port} 的設定`,
      savedDetail: (readBack) => `AirVPN 重新讀取確認：${readBack}。`,
      errors: {
        notesOneLine: "備註只能是一行文字",
        notesTooLong: (max) => `備註最多 ${max} 個字`,
        ddnsChars: "只能有英文字母、數字與連字號，連字號不能在開頭或結尾",
        ddnsTooLong: (max) => `最多 ${max} 個字`,
      },
      readBack: {
        notes: (text) => `備註「${text}」`,
        noNotes: "沒有備註",
        device: (label) => `裝置：${label}`,
        protocol: (protocol) => `協定 ${protocol}`,
        ipVersion: (layer) => `IP 版本 ${layer}`,
        noDdns: "沒有 DDNS 名稱",
        list: (parts) => parts.join("、"),
      },
    },
    sameLocalPort: (port) =>
      `App 必須在 ${port} 監聽：AirVPN 把外部連到 ${port} 的連線原樣送到這條連線的 tunnel port ${port}，P2P 程式（例如 BitTorrent）對外宣告的也是 ${port}。不要讓 App 改用別的 port，也不要把這個連入埠的 Local port 改成別的 port。`,
    remapped: (port, local) =>
      `AirVPN 把 ${port} 轉到 local port ${local}：P2P 程式必須在對外的同一個 port 監聽，請在連入埠的「設定」把 Local port 改回 ${port}。`,
    localPortDiffers: (port, local) =>
      `VPN Manager 的轉發與 P2P 程式需要和公開的 port 相同：外部連到 ${port} 的連線會被送到 tunnel 的 ${local}，App 卻要在 ${port} 監聽，P2P 程式對外宣告的也是 ${port}。`,
    websiteSteps: [
      "在瀏覽器登入 AirVPN 網站的 Client Area，打開「Ports」。",
      "保留一個 port（每個帳號最多 5 個，2049 以上），選擇 TCP、UDP 或兩者；Local port 留空。",
      "回到這裡建立轉發：tunnel port、公開 port 與 App 的 port 都填同一個 port。",
    ],
    test: {
      title: (port) => `測試連入埠 ${port}`,
      description: "AirVPN 從每條使用這個埠的連線的伺服器，連到這個埠，和 AirVPN 網站的測試相同。",
      again: "再測一次",
      running: (port) => `AirVPN 正在從伺服器連到 ${port}：每條連線最多約 15 秒。`,
      failed: "沒有完成測試",
      results: "各連線的測試結果",
      outside: "外部連到這個伺服器位址",
      deliveredTo: "送到",
      delivered: "AirVPN 送到這條連線的位址",
      device: (name) => `（裝置 ${name}）`,
      said: (message) => `AirVPN：${message}`,
      testedAt: (time) => `測試於 ${time}；AirVPN 只測試 TCP，UDP 連線沒有結果。`,
      portDisabled: "這個埠已停用",
      portDisabledHint: "AirVPN 不會轉送停用的埠：先在「設定」啟用，再測試。",
      noSession: "目前沒有 AirVPN 連線使用這個埠，沒有東西可以測試",
      steps: {
        connect: (device) =>
          `用這個帳號建立並啟動一條連線（上方「建立連線」）${device ? `；這個埠只轉給裝置「${device}」，要用那台裝置` : ""}。`,
        listen: (port) => `讓程式在 ${port} 監聽：按「建立轉發」把它轉到這條連線的受管 App，或讓 App 自己監聽。`,
        again: "再測一次。",
      },
      state: {
        open: "連得進來",
        closed: "連不進來",
        warning: "有警告",
        unknown: "結果不明",
        unknownSaid: (word) => `結果不明（AirVPN：${word}）`,
        not_tested: "沒有測試",
      },
    },
  },
  ja: {
    title: "着信ポート",
    named: (port) => `着信ポート ${port}`,
    protocol: { both: "TCP＋UDP", tcpOnly: "TCP のみ", udpOnly: "UDP のみ" },
    ipLayer: { both: "IPv4＋IPv6", ipv4Only: "IPv4 のみ", ipv6Only: "IPv6 のみ" },
    allDevices: "すべてのデバイス",
    deviceById: (id) => `デバイス ${id}…`,
    usage: (used, limit) => `${used}／${limit} 個を使用中`,
    enabled: "有効",
    serverUnknown: "AirVPN サーバー",
    retry: "再試行",
    enterRange: (min, max) => `${min}–${max} を入力してください`,
    reserve: {
      label: "着信ポートの予約",
      port: "予約するポート",
      byAirvpn: "AirVPN が選ぶ",
      chosen: "指定",
      submit: "ポートを予約",
      reserving: "予約中",
      portField: "ポート",
      limitReached: (limit) => `1 アカウントにつき最大 ${limit} 個です：先に使わなくなったポートを削除してください`,
      limitReachedElsewhere: (limit) =>
        `1 アカウントにつき最大 ${limit} 個です：先にプロバイダーページで使わなくなったポートを削除してください`,
      range: (min) => `${min}–65535 を入力してください（AirVPN はそれより小さいポートを受け付けません）`,
      taken: (port) => `このアカウントはすでに ${port} を予約しています`,
      allUsed: (limit) => `${limit} 個すべて使用中です：使わなくなったポートを削除すると、再び予約できます。`,
      hint: (limit, min) =>
        `1 アカウントにつき最大 ${limit} 個、${min} 以上です。すべての AirVPN サーバーで同じポートです。プレミアムプランの期限が切れて 10 日後に、AirVPN はこれらを解放します。`,
      reserved: (port) => `着信ポート ${port} を予約しました`,
      reservedDetail: "⋯ から「ポート転送を作成」を選ぶと、この接続の管理対象アプリに転送できます。",
      reservedFilled: "AirVPN がこのポートを予約し、フォームに入力しました。",
    },
    search: {
      label: "連続した空きポートを探す",
      count: "連続した空きポートの数",
      searching: "検索中",
      failed: "検索を完了できませんでした",
      result: (count) => `AirVPN（連続した空きポート ${count} 個を検索）`,
      hint: "検索するだけで、予約はしません。そのうちの 1 つを予約するには、上で「指定」を選んでそのポートを入力してください。",
    },
    ddns: {
      intro: "DDNS チェック：AirVPN は、各 DDNS 名が指している接続の数と、名前解決されるべきアドレスを報告します。",
      check: "DDNS を確認",
      failed: "DDNS チェックを完了できませんでした",
      none: "AirVPN から DDNS 名は報告されませんでした：ポートの ⋯ から「設定」を選んで DDNS 名を追加してから、もう一度確認してください。",
      names: "DDNS 名",
      resolvesTo: (addresses) => `名前解決先：${addresses.join("、")}`,
      unused: "このポートを使う接続がありません：名前は現在どこも指していません",
      one: "1 つの接続を指しています",
      many: (count) =>
        `${count} 個の接続がこのポートを使っています：名前の行き先が複数あり、目的の接続につながるとは限りません`,
    },
    list: {
      needEgress: "AirVPN の Web サイト経由で着信ポートを読み込むには、利用できる Provider 出口が必要です。",
      unreadable: "AirVPN の Web サイト経由で着信ポートを読み込めません",
      manageOnWebsite: "AirVPN の Web サイトで直接管理することもできます：",
      reserveOnWebsite: "AirVPN の Web サイトで自分で予約することもできます：",
      loading: "Provider 出口経由で AirVPN の Web サイトにログインし、着信ポートを読み込み中",
      readAt: (time) => `${time} に読み込み。P2P プログラムは同じポートで待ち受ける必要があります。`,
      none: "このアカウントで予約した着信ポートはまだありません",
      noneYet: "このアカウントで予約した着信ポートはまだありません。",
      noneHint: "ポートを予約すると、外部から AirVPN 経由でこのアカウントの接続に到達できるようになります。",
      refresh: "着信ポートを再読み込み",
      noConnection: "先にこのアカウントで接続を作成してください。ポート転送の受け先が必要です",
      notes: (text) => `メモ：${text}`,
      forwards: (names) => `ポート転送：${names.join("、")}`,
    },
    picker: {
      title: (account) => `AirVPN 着信ポート（アカウント「${account}」）`,
      choose: "着信ポートを選択",
      disabledOnWebsite: "このポートは AirVPN の Web サイトで無効になっています",
      hint: (usage) =>
        `${usage}（すべての AirVPN サーバーで共通）。ポートを選ぶと、トンネルポート、公開ポート、アプリのポートに入力されます。`,
    },
    remove: {
      title: (port) => `着信ポート ${port} を削除しますか？`,
      confirm: "着信ポートを削除",
      body: "AirVPN はこのポートをすぐに解放します。同じポートを再び予約できるとは限りません。このアカウントのほかの着信ポートには影響しません。",
      usedBy: (names) =>
        `ポート転送「${names.join("」「")}」がこのポートを使っています：削除すると外部から接続できなくなります。ポート転送自体は削除されません。`,
      deleted: (port) => `着信ポート ${port} を削除しました`,
      deletedDetail: "AirVPN はこのポートを解放しました。",
      intent: (port) => `着信ポート ${port} の削除`,
    },
    actions: {
      test: "テスト",
      testing: "テスト中",
      testBusy: (port) => `着信ポート ${port} をテスト中です。完了してからテストしてください`,
      forward: "ポート転送を作成",
      settings: "設定",
    },
    settings: {
      title: "着信ポートの設定",
      gone: "この着信ポートはもうアカウントにありません",
      goneHint: "別の場所で削除された可能性があります。着信ポートの一覧を再読み込みして確認してください。",
      titleOf: (port) => `着信ポート ${port} の設定`,
      description:
        "AirVPN の Web サイトの Client Area にある Ports ページと同じです。各設定は個別に送信され、保存後に再読み込みして確認します。すべての AirVPN サーバーがこの設定を使います。",
      enable: "このポートを有効にする",
      enableHint: "無効にすると AirVPN は転送しなくなりますが、予約は残ります。",
      fields: {
        notes: "メモ",
        enabled: "有効／無効",
        device: "デバイス",
        protocol: "プロトコル",
        ipVersion: "IP バージョン",
        ddnsName: "DDNS 名",
      },
      layerAsIs: (layer) => `AirVPN の現在の値は「${layer}」です。いずれかを選んだときだけ変更されます。`,
      deviceHint: "このデバイスの接続だけに転送するか、アカウントのすべてのデバイスに転送します",
      unlistedDevice: (id) => `デバイス ${id}…（一覧にありません）`,
      localPortHint: (port) => `外部から ${port} への接続は、トンネルアドレスのこのポートに届きます`,
      ddnsHint: (suffix, max) =>
        `完全な名前は「名前${suffix}」です：英字、数字、ハイフンで最大 ${max} 文字。空欄にすると削除されます`,
      notesHint: (max) => `AirVPN の Web サイトであなただけが見られます。最大 ${max} 文字。空欄にすると削除されます`,
      fixFirst: "先に印の付いた項目を修正してください。",
      unchanged: "まだどの設定も変更していません。",
      willChange: (names) => `変更する項目：${names.join("、")}（項目ごとに 1 リクエスト、その後再読み込みして確認）。`,
      saved: (port) => `着信ポート ${port} の設定を保存しました`,
      savedDetail: (readBack) => `AirVPN で再読み込みして確認：${readBack}。`,
      errors: {
        notesOneLine: "メモは 1 行のテキストにしてください",
        notesTooLong: (max) => `メモは ${max} 文字までです`,
        ddnsChars: "使えるのは英字、数字、ハイフンだけで、ハイフンは先頭と末尾に置けません",
        ddnsTooLong: (max) => `${max} 文字までです`,
      },
      readBack: {
        notes: (text) => `メモ「${text}」`,
        noNotes: "メモなし",
        device: (label) => `デバイス：${label}`,
        protocol: (protocol) => `プロトコル ${protocol}`,
        ipVersion: (layer) => `IP バージョン ${layer}`,
        noDdns: "DDNS 名なし",
        list: (parts) => parts.join("、"),
      },
    },
    sameLocalPort: (port) =>
      `アプリは ${port} で待ち受ける必要があります：AirVPN は外部から ${port} への接続を、そのままこの接続のトンネルポート ${port} に届けます。P2P プログラム（BitTorrent など）が外部に公開するのも ${port} です。アプリに別のポートを使わせたり、この着信ポートの Local port を別のポートに変更したりしないでください。`,
    remapped: (port, local) =>
      `AirVPN は ${port} をローカルポート ${local} に転送しています：P2P プログラムは外部に公開しているのと同じポートで待ち受ける必要があります。着信ポートの「設定」で Local port を ${port} に戻してください。`,
    localPortDiffers: (port, local) =>
      `VPN Manager のポート転送と P2P プログラムでは、公開ポートと同じにする必要があります：外部から ${port} への接続はトンネルの ${local} に届きますが、アプリは ${port} で待ち受ける必要があり、P2P プログラムが外部に公開するのも ${port} です。`,
    websiteSteps: [
      "ブラウザーで AirVPN の Web サイトの Client Area にログインし、「Ports」を開きます。",
      "ポートを 1 つ予約し（1 アカウントにつき最大 5 個、2049 以上）、TCP、UDP、または両方を選びます。Local port は空欄のままにします。",
      "ここに戻ってポート転送を作成します：トンネルポート、公開ポート、アプリのポートにはすべて同じポートを入力します。",
    ],
    test: {
      title: (port) => `着信ポート ${port} をテスト`,
      description:
        "AirVPN は、このポートを使う各接続のサーバーからこのポートに接続します。AirVPN の Web サイトのテストと同じです。",
      again: "もう一度テスト",
      running: (port) => `AirVPN がサーバーから ${port} に接続しています：接続ごとに最大で約 15 秒かかります。`,
      failed: "テストを完了できませんでした",
      results: "接続ごとのテスト結果",
      outside: "外部はこのサーバーアドレスに接続します",
      deliveredTo: "転送先",
      delivered: "AirVPN がこの接続に届けるアドレス",
      device: (name) => `（デバイス ${name}）`,
      said: (message) => `AirVPN：${message}`,
      testedAt: (time) => `${time} にテスト。AirVPN は TCP だけをテストするため、UDP 接続には結果がありません。`,
      portDisabled: "このポートは無効です",
      portDisabledHint: "AirVPN は無効なポートを転送しません：先に「設定」で有効にしてからテストしてください。",
      noSession: "現在このポートを使う AirVPN 接続がないため、テストするものがありません",
      steps: {
        connect: (device) =>
          `このアカウントで接続を作成して開始します（上の「接続を作成」）${device ? `。このポートはデバイス「${device}」にだけ転送されるため、そのデバイスを使ってください` : ""}。`,
        listen: (port) =>
          `プログラムが ${port} で待ち受けるようにします：「ポート転送を作成」を押してこの接続の管理対象アプリに転送するか、アプリ自身に待ち受けさせます。`,
        again: "もう一度テストします。",
      },
      state: {
        open: "接続可能",
        closed: "接続不可",
        warning: "警告あり",
        unknown: "結果不明",
        unknownSaid: (word) => `結果不明（AirVPN：${word}）`,
        not_tested: "未テスト",
      },
    },
  },
});
