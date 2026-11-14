// Text of the Port forwards page (/forwards): the states and filters of the model, the provider's side of a forward,
// the form and its checks, the actions and their notifications, the list, the inspector (its conclusion, evidence,
// counts and settings) and the AirVPN test in its footer. A .tsx: one sentence carries a link (src/i18n/README.md).
// Protocol names, `tunnel :port` and 127.0.0.1 addresses are not translated.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** How a forward's UDP reaches the App: straight into the sandbox, or relayed from a local address. */
type UdpPath = "direct" | "relayed";

/** A listening forward, for its conclusion: the names are null where they are not known. */
interface Delivery {
  /** The connection's name. */
  owner: string | null;
  /** The receiving App's name. */
  app: string | null;
  tunnelPort: number;
  targetPort: number;
  /** Each TCP connection starts with a PROXY protocol v2 header. */
  proxy: boolean;
}

const viaEn = (d: Delivery) =>
  `through tunnel :${d.tunnelPort} of ${d.owner === null ? "this connection" : `“${d.owner}”`}`;
const appEn = (d: Delivery) => (d.app === null ? "the app" : `“${d.app}”`);
const proxyEn = (d: Delivery) =>
  d.proxy
    ? " Each TCP connection starts with a PROXY protocol v2 header, from which the app learns the real source address."
    : "";

const viaZh = (d: Delivery) => `經${d.owner === null ? "這條連線" : `「${d.owner}」`}的 tunnel :${d.tunnelPort} 轉入的`;
const appZh = (d: Delivery) => `「${d.app ?? "App"}」`;
const proxyZh = (d: Delivery) =>
  d.proxy ? "每條 TCP 連線開頭先送 PROXY protocol v2 標頭，App 由它得知真正的來源位址。" : "";

const viaJa = (d: Delivery) =>
  `${d.owner === null ? "この接続" : `「${d.owner}」`}の tunnel :${d.tunnelPort} から転送された`;
const appJa = (d: Delivery) => `「${d.app ?? "アプリ"}」`;
const proxyJa = (d: Delivery) =>
  d.proxy
    ? "各 TCP 接続の先頭で PROXY protocol v2 ヘッダーを送り、アプリはそこから実際の送信元アドレスを知ります。"
    : "";

export const m = defineMessages({
  en: {
    title: "Port forwards",
    description:
      "Connections the provider forwards to the tunnel address, delivered only to a managed app on the same connection.",
    help: "A port forward listens only while the app actually holds that port on this computer, and stops at once when the app exits or another program takes the port. Inbound connections are checked against the IP blocklists and auto-ban. Select a port forward to see whether it is listening, the evidence of reachability from outside, and its counts.",
    helpText:
      "A port forward listens only while the app actually holds that port on this computer, and stops at once when the app exits or another program takes the port. Inbound connections are checked against the IP blocklists and auto-ban.",
    /** The page's primary action, and the title of the dialog it opens. */
    add: "Add port forward",
    /** After a count: "1 port forward", "3 port forwards". */
    unit: (total: number): string => (total === 1 ? "port forward" : "port forwards"),
    actionsOf: (name: string) => `Actions for ${name}`,
    /** Values shown side by side (a target's TCP and UDP addresses, connection names). */
    list: (parts: readonly string[]) => parts.join(", "),
    tunnelPort: "Tunnel port",
    publicPort: "Public port",
    /** A forward's limit of concurrent connections, and the connections it refused for it. */
    limit: "Limit",
    /** A forward that carries both protocols. */
    protocolBoth: "TCP+UDP",
    state: {
      connectionNotReady: "Connection not ready",
      targetMissing: "Target not listening",
      targetNotOwned: "Target is not an app",
      listening: "Listening",
      unsupported: "Not supported",
    },
    /** Evidence from outside: only an observed arrival counts. */
    reach: {
      observed: "Inbound from outside observed",
      unverified: "Not verified",
    },
    filter: {
      allTitle: "All port forwards",
      listeningTitle: "The worker listens on the tunnel address under a lease",
      idle: "Not listening",
      idleTitle: "Enabled, but not listening (connection not ready, target not listening, or state unknown)",
      disabledTitle: "Disabled; does not listen",
    },
    sort: {
      app: "Target app",
    },
    /** What the provider of a connection lets a forward do, and the steps to get a port there. */
    guide: {
      mullvad: "Mullvad no longer offers port forwarding; port forwards cannot be set up on this connection.",
      airvpnTitle: "AirVPN: reserve a port on the AirVPN website first",
      airvpnSteps: [
        "Sign in to the Client Area of the AirVPN website, reserve a port under “Ports”, and choose TCP, UDP or both. (This connection was not created from an AirVPN account in VPN Manager; once you add the account under “Providers” and create a connection with it, you can reserve ports right here.)",
        "The reserved port is the public port; when “Local port” is left empty, the port forwarded into the tunnel is the same one (the tunnel port). When a Local port is set, enter the Local port as the tunnel port.",
        "Here, choose the managed app that receives the connections and the port it listens on on this computer. Forwarding starts only while the app is actually listening on that port.",
      ],
      genericTitle: "Port forwarding on the WireGuard server",
      genericSteps: [
        "The VPN server has to forward the public port to this connection's tunnel address (with DNAT on the server, for example). VPN Manager does not, and cannot, set this up on the server for you.",
        "The tunnel port is the port forwarded to the tunnel address; the public port is only shown.",
      ],
    },
    /** Why a forward's UDP cannot go straight into the sandbox. */
    udpBlocked: {
      tcpOnly:
        "A TCP-only port forward has no UDP to send into the sandbox; choose UDP or TCP+UDP as the protocol to turn this on.",
      notStrictConnection:
        "Only for connections with strict isolation: this connection has no sandbox, so VPN Manager relays UDP from a local address.",
      notStrictApp: (name: string) =>
        `Only to apps with strict isolation: “${name}” is not in the connection's sandbox.`,
    },
    errors: {
      chooseConnection: "Choose a connection",
      port: "Enter 1–65535",
      publicPort: "Enter 1–65535, or leave it empty",
      appPort: "The port the app listens on must be 1024–65535",
      maxConnections: "Enter 1–16384",
      chooseApp: "Choose the managed app that receives the connections",
      appConnection: "The app must belong to the same connection",
      enforcedUdp: "An app with an enforced proxy (Seatbelt) cannot receive UDP; choose TCP",
      portTaken: (name: string) => `Already used by the port forward “${name}”`,
      udpDirectPort: (port: number) =>
        `When UDP goes straight into the sandbox, datagrams arrive unchanged at tunnel port ${port} (no address translation inside the sandbox): the app's port must equal the tunnel port`,
    },
    /** The name a forward gets when its name is left empty: by its tunnel port, when that is valid. */
    defaultName: (port: number | null) => (port === null ? "Port forward" : `Port forward ${port}`),
    actions: {
      /** Why an action waits: another intent of this forward is on its way. */
      busy: (action: string) => `“${action}” is being sent; wait until it is done`,
      disabling: "Disabling",
      test: "Test inbound",
      testing: "Testing",
      openApp: "Go to the target app",
      appNotFound: "The target app was not found",
      openInstance: "Go to its connection",
      instanceNotFound: "Its connection was not found",
      testNeedsAccount:
        "Only connections created from an AirVPN account in VPN Manager can ask AirVPN to test inbound connections",
      testTcpOnly: "AirVPN tests TCP only; this port forward receives UDP only",
    },
    /** Notifications; an intent is what a failure is reported as (the notification adds that it failed). */
    toast: {
      enabled: (name: string) => `Port forward ${name} was enabled`,
      disabled: (name: string) => `Port forward ${name} was disabled`,
      enableIntent: (name: string) => `Enable port forward ${name}`,
      disableIntent: (name: string) => `Disable port forward ${name}`,
      deleted: (name: string) => `Port forward ${name} was deleted`,
      deleteIntent: (name: string) => `Delete port forward ${name}`,
      updated: (name: string) => `Port forward ${name} was updated`,
      created: (name: string) => `Port forward ${name} was created`,
    },
    deleteConfirm: {
      title: (name: string) => `Delete the port forward “${name}”?`,
      stops: (port: number, protocol: string) =>
        `Listening on tunnel :${port} (${protocol}) stops at once, and the connections that came in through it end too.`,
      unaffected: "The managed app, its connection and the port reserved with the provider are not affected.",
    },
    page: {
      readingApps: "Reading the managed apps…",
      addAppFirst: "Add a managed app to receive the connections first",
      loading: "Loading port forwards",
      empty: "No port forwards yet",
      /** `link` draws its text as the link to the managed apps page. */
      emptyNoApps: (link: (text: string) => ReactNode): ReactNode => (
        <>
          Port forwards go only to managed apps: first go to {link("Managed apps")} and add the program that receives
          the connections.
        </>
      ),
      emptyBody:
        "Once the provider forwards a public port to this computer's tunnel address, choose here which managed app receives it (BitTorrent, a game or a web server, for example).",
      listLabel: "Port forward list",
      search: "Search port forwards",
      searchPlaceholder: "Name, port, connection or app",
      /** The list could not be refreshed: `time` is when the data on screen was read. */
      stale: (time: string) => `Cannot refresh: showing the data from ${time}`,
      noMatch: "No port forwards match",
      detailsOf: (name: string) => `Details of ${name}`,
      details: "Port forward details",
      notFound: "This port forward was not found",
      choose: "Select a port forward",
      chooseHint:
        "See whether it is listening, its target app, the evidence of reachability from outside, and its counts.",
      /** A row's public port, after its tunnel port. */
      publicAt: (port: number) => `public :${port}`,
    },
    column: {
      forward: "Port forward",
      target: "Target",
      connection: "Connection",
      reach: "Reachable from outside",
    },
    /** The inspector's footer: AirVPN's test of the forward's public port. */
    test: {
      pending: (port: number) =>
        `AirVPN is connecting to ${port} from its servers: up to about 15 seconds per connection.`,
      failed: (reason: string) => `The test did not complete: ${reason}`,
      noSessions: (port: number) =>
        `No AirVPN connection uses ${port} right now, so there is nothing to test: test again once a connection is running and using this port.`,
      resultsLabel: "AirVPN's test results",
      /** `open` is the word of AirVPN's answer that the port is open; `time` is when the test ran. */
      proof: (open: string, time: string) =>
        `Only AirVPN answering “${open}” proves it is reachable from outside; tested ${time}.`,
      request: (port: number) => `Ask AirVPN to connect to public port ${port} from its servers (TCP only).`,
      evidenceOnly:
        "Reachability from outside counts only inbound connections actually observed from outside; the configuration itself is no evidence.",
    },
    /** The inspector's conclusion: whether the forward listens and, if not, why. */
    conclusion: {
      unknown: "State unknown",
      unknownBody:
        "The core service has not reported this port forward's state; whether it is listening cannot be confirmed.",
      unsupported: "This connection cannot forward ports",
      disabledBody:
        "It does not listen; once enabled, it starts listening while the connection is running and the app holds this port.",
      /** TCP, UDP or both, relayed to the App's local port. */
      relayed: (d: Delivery, protocol: string) =>
        `${protocol} connections coming in ${viaEn(d)} go to ${appEn(d)} at 127.0.0.1:${d.targetPort}.${proxyEn(d)}`,
      tcpRelayedUdpDirect: (d: Delivery) =>
        `TCP connections coming in ${viaEn(d)} go to ${appEn(d)} at 127.0.0.1:${d.targetPort}; UDP goes straight into the sandbox, and the app receives it on its own socket on :${d.tunnelPort}, with the real source address.${proxyEn(d)}`,
      udpDirect: (d: Delivery) =>
        `UDP coming in ${viaEn(d)} goes straight into the sandbox, and ${appEn(d)} receives it on its own socket on :${d.tunnelPort}, with the real source address.${proxyEn(d)}`,
    },
    inspector: {
      idLabel: "Port forward ID",
      observedAt: (time: string) => `Observed ${time}`,
      lastSeen: (absolute: string, relative: string) => `Last seen ${absolute} (${relative})`,
      reachHint:
        "Only connections from outside the tunnel and private networks count; the configuration itself is no evidence",
      /** After the reachability: the protocols an arrival from outside was observed on. */
      observedOver: { both: " (TCP, UDP)", tcp: " (TCP)", udp: " (UDP)" },
      targetHint: (pid: number | null, time: string, wildcard: boolean) =>
        `PID ${pid ?? "—"} · verified ${time}${wildcard ? " · the app listens on every address (other hosts can connect too)" : ""}`,
      targetPending: "Granted once the connection is ready and the app holds the port",
      lease: "Lease",
      leaseHint: (generation: number, time: string) => `Generation ${generation} · since ${time}`,
    },
    counters: {
      title: "Counts of this generation",
      accepted: "Forwarded",
      active: (tcp: number, udp: number) => `Active: TCP ${tcp} · UDP ${udp}`,
      traffic: "Traffic",
      trafficHint: "Into the app / sent by the app",
      bytes: (inbound: string, outbound: string) => `${inbound} / ${outbound}`,
      refused: "Refused",
      blocklisted: "IP blocklist",
      banned: "Auto-ban",
      closed: "Not open",
      targetFailed: "App did not accept",
      udpDropped: "UDP dropped",
      noWorker: "The connection has no running worker, so there are no counts.",
      unknown: "Unknown.",
    },
    settings: {
      title: "Settings",
      app: "Managed app",
      appUdpDirect: (port: number) => `UDP :${port} (the app's own socket)`,
      appBothDirect: (targetPort: number, tunnelPort: number) =>
        `TCP 127.0.0.1:${targetPort} · UDP :${tunnelPort} (the app's own socket)`,
      publicPortHint: "Entered by hand, not verified by the provider",
      notSet: "Not set",
      limitHint: "TCP connections and UDP flows are counted separately",
      source: "Source address",
      /** How the App learns who connected. `udp`: where a forward of both protocols sends UDP (null: TCP or UDP only). */
      sourceHint: {
        proxy: (udp: UdpPath | null) =>
          `At the start of each TCP connection; the app must support it, or its connections fail${udp === "direct" ? " · UDP goes straight into the sandbox and carries the real source too" : udp === "relayed" ? " · UDP is relayed as usual" : ""}`,
        udpOnlyDirect: "UDP goes straight into the sandbox and arrives at the app's own socket",
        udpDirect:
          "UDP goes straight into the sandbox; TCP connections see a local address as their source (to tell TCP too, turn on PROXY protocol v2)",
        local: "The app sees a local address as the source of everything",
      },
      sourceValue: {
        proxy: "Passed to the app with PROXY protocol v2",
        real: "The app receives the real source address",
        udpOnly: "Only UDP carries the real source address",
        none: "Not passed to the app",
      },
      udpDirectHint:
        "Delivered unchanged to the app's own socket on the tunnel port: only while the lease is valid and the connection is open, with the sources checked against the IP blocklists and auto-ban",
      udpRelayedHint:
        "Relayed by VPN Manager from a local address: the app sees a local address as the source of everything",
      udpDirect: "Straight into the sandbox",
      udpRelayed: "Relayed from a local address",
      provider: "Provider",
      providerHint: "Inbound ports and tests go through this account",
      airvpnWithoutAccount: "AirVPN (the connection was not created from an account in VPN Manager)",
      generic: "WireGuard: the server forwards the public port to the tunnel address",
    },
    dialog: {
      editTitle: (name: string) => `Edit port forward ${name}`,
      description:
        "Connections that come in through this connection's tunnel address go to the port a managed app of the same connection listens on, on this computer. The forward listens only while the app actually holds that port; no other program ever receives them.",
      create: "Create port forward",
      chooseConnection: "Choose a connection…",
      blocked: "Port forwards cannot be set up on this connection",
      /** The public port came from AirVPN's reserved ports. */
      mustListen: (port: number) => `The app must listen on ${port}`,
      protocol: "Protocol",
      /** What each protocol is for, on its choice card. */
      protocolUse: {
        tcp: "Most services (web, SSH, game servers)",
        udp: "DHT, voice and some games, for example",
        both: "BitTorrent, for example (TCP and UDP on the same port)",
      },
      tcpOnly: "An app with an enforced proxy receives TCP only",
      enforcedNote: (name: string) =>
        `“${name}” uses an enforced proxy (macOS Seatbelt): it receives TCP only, and the app must listen on 127.0.0.1 only; listening on every address (0.0.0.0) gets it stopped within about 2 seconds. For UDP (BitTorrent's DHT, for example), use strict isolation on Linux instead.`,
      /** What a strictly isolated App must hold for the forward; `port` is the App's port. */
      strict: {
        loopbackTitle: (port: string) => `A strictly isolated app has to listen on ${port} at 127.0.0.1`,
        loopbackBody:
          "It shares the network with this connection: listening on every address (0.0.0.0) takes the very port the forward has to receive on at the tunnel address, and neither side can use it.",
        udpTitle: (port: string) => `A strictly isolated app has to receive UDP ${port} on every address`,
        udpBody:
          "UDP goes straight into the sandbox: datagrams arrive at the tunnel address, so the app has to receive on 0.0.0.0 (or the tunnel address); on 127.0.0.1 alone it receives nothing.",
        bothTitle: (port: string) =>
          `A strictly isolated app receives ${port} with TCP on 127.0.0.1 and UDP on every address`,
        bothBody:
          "The forward connects TCP in from 127.0.0.1: listening for TCP on every address takes the very port the forward holds at the tunnel address. UDP goes straight into the sandbox, so the app has to receive it on 0.0.0.0 (or the tunnel address).",
      },
      tunnelPortHint: "The port the provider forwards to the tunnel address (AirVPN's Local port)",
      publicPortHint: "The port facing outside at the provider; only shown, never verified",
      publicPortPlaceholder: "Same as the tunnel port",
      app: "Receiving managed app",
      noApps: "This connection has no managed apps yet; add one first",
      chooseApp: "Choose an app…",
      appPort: "App port",
      appPortHint: "The port the app listens on, on this computer",
      nameHint: (name: string) => `Left empty, “${name}” is used`,
      maxConnections: "Concurrent connection limit",
      maxConnectionsHint: "TCP connections and UDP flows are counted separately, 1–16384",
      enabledHint:
        "Starts listening while the connection is running and the app holds this port; disabling stops it at once and ends its connections.",
      proxy: "Pass the source address to the app (PROXY protocol v2)",
      /** `udp`: where a forward of both protocols sends UDP (null: TCP only). */
      proxyHint: (udp: UdpPath | null) =>
        `Each TCP connection starts with a header that tells the app the real source address (otherwise the app sees a local address for every connection). The app must support PROXY protocol v2, or its connections fail.${udp === "direct" ? " UDP gets no header (it goes straight into the sandbox; see below)." : udp === "relayed" ? " UDP is relayed as usual." : ""}`,
      proxyUdpOnly: "PROXY protocol goes on TCP connections only; it cannot be turned on for a UDP-only forward.",
      udpDirect: "UDP straight into the sandbox",
      /** `both`: the forward carries TCP too. */
      udpDirectHint: (both: boolean) =>
        `UDP is not relayed from a local address: datagrams arrive unchanged at the app's own socket on the tunnel port, so the app sees the real source address and replies from the same port (eMule's Kad and BitTorrent's DHT need this). The app has to receive on every address (0.0.0.0) or the tunnel address, and the app's port must equal the tunnel port; the sources go through the IP blocklists and auto-ban all the same.${both ? " TCP is relayed as usual." : ""}`,
    },
  },
  "zh-TW": {
    title: "轉發",
    description: "供應商轉到 tunnel 位址的連線，只送到同一條連線的受管 App。",
    help: "App 確實在本機持有那個 port 時才監聽，App 結束或 port 被其他程式取得時立即停止。轉入的連線經 IP 封鎖清單與自動封鎖檢查。選一個轉發查看它是否在監聽、外部可達的證據與計數。",
    helpText:
      "App 確實在本機持有那個 port 時才監聽，App 結束或 port 被其他程式取得時立即停止。轉入的連線經 IP 封鎖清單與自動封鎖檢查。",
    add: "新增轉發",
    unit: () => "個轉發",
    actionsOf: (name) => `${name} 的操作`,
    list: (parts) => parts.join("、"),
    tunnelPort: "tunnel port",
    publicPort: "公開 port",
    limit: "上限",
    protocolBoth: "TCP＋UDP",
    state: {
      connectionNotReady: "連線未就緒",
      targetMissing: "目標未監聽",
      targetNotOwned: "目標不是 App",
      listening: "監聽中",
      unsupported: "不支援",
    },
    reach: {
      observed: "已觀測外部連入",
      unverified: "未驗證",
    },
    filter: {
      allTitle: "所有轉發",
      listeningTitle: "worker 以租約在 tunnel 位址監聽",
      idle: "未監聽",
      idleTitle: "已啟用，但沒有在監聽（連線未就緒、目標未監聽或狀態未知）",
      disabledTitle: "已停用，不會監聽",
    },
    sort: {
      app: "目標 App",
    },
    guide: {
      mullvad: "Mullvad 已停止提供 port forwarding，這條連線不能設定轉發。",
      airvpnTitle: "AirVPN：先在 AirVPN 網站保留 port",
      airvpnSteps: [
        "登入 AirVPN 網站的 Client Area，在「Ports」保留一個 port，並選擇 TCP、UDP 或兩者。（這條連線不是由 VPN Manager 裡的 AirVPN 帳號建立的；在「供應商」加入帳號並用它建立連線後，就能直接在這裡保留。）",
        "保留的 port 是公開 port；「Local port」留空時，轉入 tunnel 的也是同一個 port（tunnel port）。有設定 Local port 時，tunnel port 填 Local port。",
        "在這裡選擇接收連線的受管 App 與它在本機監聽的 port。只有 App 確實在那個 port 監聽時才會開始轉發。",
      ],
      genericTitle: "WireGuard 伺服器端的轉發",
      genericSteps: [
        "VPN 伺服器必須把公開 port 轉到這條連線的 tunnel 位址（例如在伺服器設定 DNAT）。VPN Manager 不會、也無法替你在伺服器上設定。",
        "tunnel port 是轉到 tunnel 位址的 port；公開 port 只做顯示。",
      ],
    },
    udpBlocked: {
      tcpOnly: "只轉發 TCP 時沒有 UDP 可以送進沙箱；協定選 UDP 或 TCP＋UDP 後才能開啟。",
      notStrictConnection: "只用於嚴格隔離的連線：這條連線沒有沙箱，UDP 由 VPN Manager 從本機位址轉送。",
      notStrictApp: (name) => `只送到嚴格隔離的 App：「${name}」不在連線的沙箱裡。`,
    },
    errors: {
      chooseConnection: "請選擇連線",
      port: "請輸入 1–65535",
      publicPort: "請輸入 1–65535，或留空",
      appPort: "App 監聽的 port 必須是 1024–65535",
      maxConnections: "請輸入 1–16384",
      chooseApp: "請選擇接收連線的受管 App",
      appConnection: "App 必須屬於同一條連線",
      enforcedUdp: "強制代理（Seatbelt）的 App 不能接收 UDP；請選 TCP",
      portTaken: (name) => `已由轉發「${name}」使用`,
      udpDirectPort: (port) =>
        `UDP 直接送進沙箱時，datagram 原樣送到 tunnel port ${port}（沙箱內不轉換位址）：App 的 port 必須等於 tunnel port`,
    },
    defaultName: (port) => (port === null ? "轉發" : `轉發 ${port}`),
    actions: {
      busy: (action) => `正在送出「${action}」，完成後再操作`,
      disabling: "停用中",
      test: "測試連入",
      testing: "測試中",
      openApp: "前往目標 App",
      appNotFound: "找不到目標 App",
      openInstance: "前往所屬連線",
      instanceNotFound: "找不到所屬連線",
      testNeedsAccount: "只有由 VPN Manager 裡的 AirVPN 帳號建立的連線，可以請 AirVPN 測試連入",
      testTcpOnly: "AirVPN 只測試 TCP；這個轉發只收 UDP",
    },
    toast: {
      enabled: (name) => `已啟用轉發 ${name}`,
      disabled: (name) => `已停用轉發 ${name}`,
      enableIntent: (name) => `啟用轉發 ${name}`,
      disableIntent: (name) => `停用轉發 ${name}`,
      deleted: (name) => `已刪除轉發 ${name}`,
      deleteIntent: (name) => `刪除轉發 ${name}`,
      updated: (name) => `已更新轉發 ${name}`,
      created: (name) => `已建立轉發 ${name}`,
    },
    deleteConfirm: {
      title: (name) => `刪除轉發「${name}」？`,
      stops: (port, protocol) => `tunnel :${port}（${protocol}）會立即停止監聽，經它轉入的連線也會結束。`,
      unaffected: "受管 App、所屬連線，以及供應商那邊保留的 port 都不受影響。",
    },
    page: {
      readingApps: "正在讀取受管 App…",
      addAppFirst: "先新增要接收連線的受管 App",
      loading: "載入轉發",
      empty: "還沒有轉發",
      emptyNoApps: (link) => <>轉發只送到受管 App：先到{link("受管 App")}新增要接收連線的程式。</>,
      emptyBody:
        "供應商把公開 port 轉到這台電腦的 tunnel 位址後，在這裡指定由哪個受管 App 接收（例如 BitTorrent、遊戲或網頁伺服器）。",
      listLabel: "轉發清單",
      search: "搜尋轉發",
      searchPlaceholder: "名稱、port、連線或 App",
      stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
      noMatch: "沒有符合條件的轉發",
      detailsOf: (name) => `${name} 的詳細資料`,
      details: "轉發詳細資料",
      notFound: "找不到這個轉發",
      choose: "選擇一個轉發",
      chooseHint: "查看它是否在監聽、目標 App、外部可達的證據與計數。",
      publicAt: (port) => `公開 :${port}`,
    },
    column: {
      forward: "轉發",
      target: "目標",
      connection: "連線",
      reach: "外部可達",
    },
    test: {
      pending: (port) => `AirVPN 正在從伺服器連到 ${port}：每條連線最多約 15 秒。`,
      failed: (reason) => `沒有完成測試：${reason}`,
      noSessions: (port) => `目前沒有 AirVPN 連線使用 ${port}，沒有東西可以測試：連線執行並使用這個埠後再測一次。`,
      resultsLabel: "AirVPN 的測試結果",
      proof: (open, time) => `只有 AirVPN 回答「${open}」才證明外部連得到；${time}測試。`,
      request: (port) => `請 AirVPN 從它的伺服器連到公開 port ${port}（只測 TCP）。`,
      evidenceOnly: "外部可達只看實際觀測到的外部連入；設定本身不是證據。",
    },
    conclusion: {
      unknown: "狀態未知",
      unknownBody: "核心服務沒有回報這個轉發的狀態；轉發是否在監聽無法確認。",
      unsupported: "這條連線不能轉發",
      disabledBody: "不會監聽；啟用後，連線執行中且 App 持有這個 port 時開始監聽。",
      relayed: (d, protocol) =>
        `${viaZh(d)} ${protocol} 連線，送到${appZh(d)} 127.0.0.1:${d.targetPort}。${proxyZh(d)}`,
      tcpRelayedUdpDirect: (d) =>
        `${viaZh(d)} TCP 連線送到${appZh(d)} 127.0.0.1:${d.targetPort}；UDP 直接送進沙箱，由 App 自己在 :${d.tunnelPort} 的 socket 收到真正的來源位址。${proxyZh(d)}`,
      udpDirect: (d) =>
        `${viaZh(d)} UDP 直接送進沙箱，由${appZh(d)}自己在 :${d.tunnelPort} 的 socket 收到真正的來源位址。${proxyZh(d)}`,
    },
    inspector: {
      idLabel: "轉發 ID",
      observedAt: (time) => `${time}觀測`,
      lastSeen: (absolute, relative) => `最近一次 ${absolute}（${relative}）`,
      reachHint: "只有來自 tunnel 與私有網段以外的連入才算；設定本身不是證據",
      observedOver: { both: "（TCP、UDP）", tcp: "（TCP）", udp: "（UDP）" },
      targetHint: (pid, time, wildcard) =>
        `PID ${pid ?? "—"} · ${time}核對${wildcard ? " · App 在所有位址監聽（其他主機也連得到）" : ""}`,
      targetPending: "連線就緒、App 持有 port 後才會核准",
      lease: "租約",
      leaseHint: (generation, time) => `第 ${generation} 代 · ${time} 起`,
    },
    counters: {
      title: "這一代的計數",
      accepted: "已轉送",
      active: (tcp, udp) => `進行中 TCP ${tcp} · UDP ${udp}`,
      traffic: "流量",
      trafficHint: "轉入 App／App 送出",
      bytes: (inbound, outbound) => `${inbound}／${outbound}`,
      refused: "已拒絕",
      blocklisted: "IP 封鎖清單",
      banned: "自動封鎖",
      closed: "未開放",
      targetFailed: "App 未接受",
      udpDropped: "UDP 丟棄",
      noWorker: "連線沒有執行中的 worker，沒有計數。",
      unknown: "未知。",
    },
    settings: {
      title: "設定",
      app: "受管 App",
      appUdpDirect: (port) => `UDP :${port}（App 自己的 socket）`,
      appBothDirect: (targetPort, tunnelPort) =>
        `TCP 127.0.0.1:${targetPort} · UDP :${tunnelPort}（App 自己的 socket）`,
      publicPortHint: "手動登錄，沒有供應商核實",
      notSet: "未填",
      limitHint: "TCP 連線與 UDP 流量各自計算",
      source: "來源位址",
      sourceHint: {
        proxy: (udp) =>
          `每條 TCP 連線開頭；App 必須支援，否則連線會失敗${udp === "direct" ? " · UDP 直接送進沙箱，也帶真正的來源" : udp === "relayed" ? " · UDP 照常轉送" : ""}`,
        udpOnlyDirect: "UDP 直接送進沙箱，由 App 自己的 socket 收到",
        udpDirect: "UDP 直接送進沙箱；TCP 連線看到的來源是本機位址（要讓 TCP 也知道，開啟 PROXY protocol v2）",
        local: "App 看到的來源都是本機位址",
      },
      sourceValue: {
        proxy: "以 PROXY protocol v2 傳給 App",
        real: "App 收到真正的來源位址",
        udpOnly: "只有 UDP 帶真正的來源位址",
        none: "不傳給 App",
      },
      udpDirectHint:
        "原樣送到 App 自己在 tunnel port 的 socket：只在租約有效、連線開放時，來源經 IP 封鎖清單與自動封鎖",
      udpRelayedHint: "由 VPN Manager 從本機位址轉送：App 看到的來源都是本機位址",
      udpDirect: "直接送進沙箱",
      udpRelayed: "經本機位址轉送",
      provider: "供應商",
      providerHint: "連入埠與測試都經這個帳號",
      airvpnWithoutAccount: "AirVPN（連線不是由 VPN Manager 裡的帳號建立）",
      generic: "WireGuard：伺服器端把公開 port 轉到 tunnel 位址",
    },
    dialog: {
      editTitle: (name) => `編輯轉發 ${name}`,
      description:
        "經這條連線的 tunnel 位址轉入的連線，轉到同一條連線的受管 App 在本機監聽的 port。只有 App 確實持有那個 port 時才會監聽；其他程式永遠收不到。",
      create: "建立轉發",
      chooseConnection: "選擇連線…",
      blocked: "這條連線不能設定轉發",
      mustListen: (port) => `App 必須在 ${port} 監聽`,
      protocol: "協定",
      protocolUse: {
        tcp: "大多數服務（網頁、SSH、遊戲伺服器）",
        udp: "例如 DHT、語音、部分遊戲",
        both: "例如 BitTorrent（同一個 port 收 TCP 與 UDP）",
      },
      tcpOnly: "強制代理的 App 只能收 TCP",
      enforcedNote: (name) =>
        `「${name}」用強制代理（macOS Seatbelt）：只能收 TCP，而且 App 必須只在 127.0.0.1 監聽，在所有位址（0.0.0.0）監聽會在約 2 秒內被停止。需要 UDP（例如 BitTorrent 的 DHT）請改用 Linux 的嚴格隔離。`,
      strict: {
        loopbackTitle: (port) => `嚴格隔離的 App 要在 127.0.0.1 監聽 ${port}`,
        loopbackBody:
          "它與這條連線共用網路：在所有位址（0.0.0.0）監聽會占住轉發要在 tunnel 位址接收的同一個 port，兩邊都無法使用。",
        udpTitle: (port) => `嚴格隔離的 App 要在所有位址接收 UDP ${port}`,
        udpBody:
          "UDP 直接送進沙箱：datagram 送到 tunnel 位址，App 要在 0.0.0.0（或 tunnel 位址）接收；只在 127.0.0.1 收不到。",
        bothTitle: (port) => `嚴格隔離的 App：TCP 在 127.0.0.1、UDP 在所有位址接收 ${port}`,
        bothBody:
          "TCP 由轉發從 127.0.0.1 連入：在所有位址監聽 TCP 會占住轉發在 tunnel 位址保留的同一個 port。UDP 直接送進沙箱，App 要在 0.0.0.0（或 tunnel 位址）接收。",
      },
      tunnelPortHint: "供應商轉到 tunnel 位址的 port（AirVPN 的 Local port）",
      publicPortHint: "供應商那邊對外的 port；只做顯示，不會被核實",
      publicPortPlaceholder: "同 tunnel port",
      app: "接收的受管 App",
      noApps: "這條連線還沒有受管 App；先新增一個",
      chooseApp: "選擇 App…",
      appPort: "App 的 port",
      appPortHint: "App 在本機監聽的 port",
      nameHint: (name) => `留空會使用「${name}」`,
      maxConnections: "同時連線上限",
      maxConnectionsHint: "TCP 連線與 UDP 流量各自計算，1–16384",
      enabledHint: "連線執行中、且 App 持有這個 port 時開始監聽；停用會立即停止並結束它的連線。",
      proxy: "把來源位址傳給 App（PROXY protocol v2）",
      proxyHint: (udp) =>
        `每條 TCP 連線開頭先送一個標頭，告訴 App 真正的來源位址（否則 App 看到的都是本機位址）。App 必須支援 PROXY protocol v2，否則連線會失敗。${udp === "direct" ? "UDP 不加標頭（直接送進沙箱，見下方）。" : udp === "relayed" ? "UDP 照常轉送。" : ""}`,
      proxyUdpOnly: "PROXY protocol 只加在 TCP 連線上；只轉發 UDP 時不能開啟。",
      udpDirect: "UDP 直接送進沙箱",
      udpDirectHint: (both) =>
        `UDP 不經本機位址轉送，datagram 原樣送到 App 自己在 tunnel port 的 socket：App 看到真正的來源位址並從同一個 port 回覆（eMule 的 Kad、BitTorrent 的 DHT 需要）。App 要在所有位址（0.0.0.0）或 tunnel 位址接收，App 的 port 必須等於 tunnel port；來源同樣經 IP 封鎖清單與自動封鎖。${both ? "TCP 照常轉送。" : ""}`,
    },
  },
  ja: {
    title: "ポート転送",
    description: "プロバイダーがトンネルアドレスへ転送した接続を、同じ接続の管理対象アプリにだけ届けます。",
    help: "アプリが実際にこのコンピューターでそのポートを保持している間だけ待ち受け、アプリが終了するか、ほかのプログラムがポートを取得するとすぐに停止します。転送されてきた接続は IP ブロックリストと自動ブロックで確認されます。ポート転送を選ぶと、待ち受けているかどうか、外部からの到達のエビデンス、カウントを確認できます。",
    helpText:
      "アプリが実際にこのコンピューターでそのポートを保持している間だけ待ち受け、アプリが終了するか、ほかのプログラムがポートを取得するとすぐに停止します。転送されてきた接続は IP ブロックリストと自動ブロックで確認されます。",
    add: "ポート転送を追加",
    unit: () => "件のポート転送",
    actionsOf: (name) => `${name} の操作`,
    list: (parts) => parts.join("、"),
    tunnelPort: "トンネルポート",
    publicPort: "公開ポート",
    limit: "上限",
    protocolBoth: "TCP＋UDP",
    state: {
      connectionNotReady: "接続が未準備",
      targetMissing: "転送先の待ち受けなし",
      targetNotOwned: "転送先がアプリではない",
      listening: "待ち受け中",
      unsupported: "非対応",
    },
    reach: {
      observed: "外部からの着信を観測",
      unverified: "未検証",
    },
    filter: {
      allTitle: "すべてのポート転送",
      listeningTitle: "worker がリースを得てトンネルアドレスで待ち受けています",
      idle: "待ち受けなし",
      idleTitle: "有効ですが、待ち受けていません（接続が未準備、転送先の待ち受けなし、または状態不明）",
      disabledTitle: "無効。待ち受けません",
    },
    sort: {
      app: "転送先アプリ",
    },
    guide: {
      mullvad: "Mullvad はポートフォワーディングの提供を終了したため、この接続ではポート転送を設定できません。",
      airvpnTitle: "AirVPN：先に AirVPN の Web サイトでポートを予約してください",
      airvpnSteps: [
        "AirVPN の Web サイトの Client Area にログインし、「Ports」でポートを 1 つ予約して、TCP、UDP、または両方を選びます。（この接続は VPN Manager 内の AirVPN アカウントで作成されたものではありません。「プロバイダー」でアカウントを追加し、そのアカウントで接続を作成すると、ここで直接予約できます。）",
        "予約したポートが公開ポートです。「Local port」が空欄のときは、トンネルへ転送されるのも同じポート（トンネルポート）です。Local port を設定した場合は、トンネルポートに Local port を入力します。",
        "ここで、接続を受け取る管理対象アプリと、そのアプリがこのコンピューターで待ち受けるポートを選びます。アプリが実際にそのポートで待ち受けている間だけ転送が行われます。",
      ],
      genericTitle: "WireGuard サーバー側のポート転送",
      genericSteps: [
        "VPN サーバーが公開ポートをこの接続のトンネルアドレスへ転送する必要があります（例：サーバーで DNAT を設定）。VPN Manager がサーバー側を設定することはなく、設定することもできません。",
        "トンネルポートはトンネルアドレスへ転送されるポートです。公開ポートは表示のみに使われます。",
      ],
    },
    udpBlocked: {
      tcpOnly:
        "TCP だけを転送する場合、サンドボックスへ送る UDP はありません。プロトコルで UDP または TCP＋UDP を選ぶと有効にできます。",
      notStrictConnection:
        "厳格な分離の接続専用です。この接続にはサンドボックスがなく、UDP は VPN Manager がローカルアドレスから中継します。",
      notStrictApp: (name) => `厳格な分離のアプリにだけ送ります。「${name}」は接続のサンドボックス内にありません。`,
    },
    errors: {
      chooseConnection: "接続を選択してください",
      port: "1–65535 を入力してください",
      publicPort: "1–65535 を入力するか、空欄にしてください",
      appPort: "アプリが待ち受けるポートは 1024–65535 にしてください",
      maxConnections: "1–16384 を入力してください",
      chooseApp: "接続を受け取る管理対象アプリを選択してください",
      appConnection: "アプリは同じ接続に属している必要があります",
      enforcedUdp: "強制プロキシ（Seatbelt）のアプリは UDP を受信できません。TCP を選んでください",
      portTaken: (name) => `ポート転送「${name}」が使用中です`,
      udpDirectPort: (port) =>
        `UDP をサンドボックスへ直接送る場合、データグラムはそのままトンネルポート ${port} に届きます（サンドボックス内ではアドレスを変換しません）。アプリのポートはトンネルポートと同じにしてください`,
    },
    defaultName: (port) => (port === null ? "ポート転送" : `ポート転送 ${port}`),
    actions: {
      busy: (action) => `「${action}」を送信中です。完了してから操作してください`,
      disabling: "無効化中",
      test: "着信をテスト",
      testing: "テスト中",
      openApp: "転送先アプリへ移動",
      appNotFound: "転送先アプリが見つかりません",
      openInstance: "所属する接続へ移動",
      instanceNotFound: "所属する接続が見つかりません",
      testNeedsAccount:
        "AirVPN に着信のテストを依頼できるのは、VPN Manager 内の AirVPN アカウントで作成した接続だけです",
      testTcpOnly: "AirVPN は TCP だけをテストします。このポート転送は UDP だけを受信します",
    },
    toast: {
      enabled: (name) => `ポート転送 ${name} を有効にしました`,
      disabled: (name) => `ポート転送 ${name} を無効にしました`,
      enableIntent: (name) => `ポート転送 ${name} の有効化`,
      disableIntent: (name) => `ポート転送 ${name} の無効化`,
      deleted: (name) => `ポート転送 ${name} を削除しました`,
      deleteIntent: (name) => `ポート転送 ${name} の削除`,
      updated: (name) => `ポート転送 ${name} を更新しました`,
      created: (name) => `ポート転送 ${name} を作成しました`,
    },
    deleteConfirm: {
      title: (name) => `ポート転送「${name}」を削除しますか？`,
      stops: (port, protocol) =>
        `tunnel :${port}（${protocol}）での待ち受けはすぐに停止し、そこから転送されてきた接続も終了します。`,
      unaffected: "管理対象アプリ、所属する接続、プロバイダー側で予約したポートには影響しません。",
    },
    page: {
      readingApps: "管理対象アプリを読み込んでいます…",
      addAppFirst: "先に、接続を受け取る管理対象アプリを追加してください",
      loading: "ポート転送を読み込み中",
      empty: "ポート転送はまだありません",
      emptyNoApps: (link) => (
        <>
          ポート転送は管理対象アプリにだけ届きます。先に{link("管理対象アプリ")}
          で、接続を受け取るプログラムを追加してください。
        </>
      ),
      emptyBody:
        "プロバイダーが公開ポートをこのコンピューターのトンネルアドレスへ転送したら、どの管理対象アプリが受け取るかをここで指定します（例：BitTorrent、ゲーム、Web サーバー）。",
      listLabel: "ポート転送の一覧",
      search: "ポート転送を検索",
      searchPlaceholder: "名前、ポート、接続、アプリ",
      stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
      noMatch: "条件に一致するポート転送はありません",
      detailsOf: (name) => `${name} の詳細`,
      details: "ポート転送の詳細",
      notFound: "このポート転送が見つかりません",
      choose: "ポート転送を選択",
      chooseHint: "待ち受けているかどうか、転送先アプリ、外部からの到達のエビデンス、カウントを確認できます。",
      publicAt: (port) => `公開 :${port}`,
    },
    column: {
      forward: "ポート転送",
      target: "転送先",
      connection: "接続",
      reach: "外部からの到達",
    },
    test: {
      pending: (port) => `AirVPN がサーバーから ${port} に接続しています。1 接続あたり最大約 15 秒かかります。`,
      failed: (reason) => `テストが完了しませんでした：${reason}`,
      noSessions: (port) =>
        `現在 ${port} を使用している AirVPN 接続がないため、テストできるものがありません。接続を実行してこのポートを使用してから、もう一度テストしてください。`,
      resultsLabel: "AirVPN のテスト結果",
      proof: (open, time) =>
        `AirVPN が「${open}」と答えた場合だけ、外部から到達できることの証明になります（${time}のテスト）。`,
      request: (port) => `AirVPN のサーバーから公開ポート ${port} に接続してもらいます（TCP のみ）。`,
      evidenceOnly:
        "外部からの到達は、実際に観測された外部からの着信だけで判断します。設定そのものはエビデンスになりません。",
    },
    conclusion: {
      unknown: "状態不明",
      unknownBody: "コアサービスがこのポート転送の状態を報告していないため、待ち受けているかどうかを確認できません。",
      unsupported: "この接続ではポート転送できません",
      disabledBody:
        "待ち受けません。有効にすると、接続が実行中でアプリがこのポートを保持している間、待ち受けを開始します。",
      relayed: (d, protocol) =>
        `${viaJa(d)} ${protocol} 接続は、${appJa(d)}の 127.0.0.1:${d.targetPort} に届きます。${proxyJa(d)}`,
      tcpRelayedUdpDirect: (d) =>
        `${viaJa(d)} TCP 接続は、${appJa(d)}の 127.0.0.1:${d.targetPort} に届きます。UDP はサンドボックスへ直接送られ、アプリ自身の :${d.tunnelPort} のソケットが実際の送信元アドレスとともに受信します。${proxyJa(d)}`,
      udpDirect: (d) =>
        `${viaJa(d)} UDP はサンドボックスへ直接送られ、${appJa(d)}自身の :${d.tunnelPort} のソケットが実際の送信元アドレスとともに受信します。${proxyJa(d)}`,
    },
    inspector: {
      idLabel: "ポート転送 ID",
      observedAt: (time) => `${time}の観測`,
      lastSeen: (absolute, relative) => `最終観測 ${absolute}（${relative}）`,
      reachHint: "トンネルとプライベートネットワーク以外からの着信だけが対象です。設定そのものはエビデンスになりません",
      observedOver: { both: "（TCP、UDP）", tcp: "（TCP）", udp: "（UDP）" },
      targetHint: (pid, time, wildcard) =>
        `PID ${pid ?? "—"} · ${time}の確認${wildcard ? " · アプリはすべてのアドレスで待ち受けています（ほかのホストからも接続できます）" : ""}`,
      targetPending: "接続が準備完了になり、アプリがポートを保持すると許可されます",
      lease: "リース",
      leaseHint: (generation, time) => `第 ${generation} 世代 · ${time} から`,
    },
    counters: {
      title: "この世代のカウント",
      accepted: "転送済み",
      active: (tcp, udp) => `処理中 TCP ${tcp} · UDP ${udp}`,
      traffic: "トラフィック",
      trafficHint: "アプリへの転送／アプリからの送信",
      bytes: (inbound, outbound) => `${inbound}／${outbound}`,
      refused: "拒否",
      blocklisted: "IP ブロックリスト",
      banned: "自動ブロック",
      closed: "未開放",
      targetFailed: "アプリが受け付けず",
      udpDropped: "UDP 破棄",
      noWorker: "接続に実行中の worker がないため、カウントはありません。",
      unknown: "不明。",
    },
    settings: {
      title: "設定",
      app: "管理対象アプリ",
      appUdpDirect: (port) => `UDP :${port}（アプリ自身のソケット）`,
      appBothDirect: (targetPort, tunnelPort) =>
        `TCP 127.0.0.1:${targetPort} · UDP :${tunnelPort}（アプリ自身のソケット）`,
      publicPortHint: "手動で登録。プロバイダーによる確認はありません",
      notSet: "未入力",
      limitHint: "TCP 接続と UDP フローをそれぞれ数えます",
      source: "送信元アドレス",
      sourceHint: {
        proxy: (udp) =>
          `各 TCP 接続の先頭。アプリが対応していないと接続は失敗します${udp === "direct" ? " · UDP はサンドボックスへ直接送られ、実際の送信元も届きます" : udp === "relayed" ? " · UDP は通常どおり中継" : ""}`,
        udpOnlyDirect: "UDP はサンドボックスへ直接送られ、アプリ自身のソケットが受信します",
        udpDirect:
          "UDP はサンドボックスへ直接送られます。TCP 接続から見える送信元はローカルアドレスです（TCP にも伝えるには PROXY protocol v2 を有効にします）",
        local: "アプリから見える送信元はすべてローカルアドレスです",
      },
      sourceValue: {
        proxy: "PROXY protocol v2 でアプリに渡す",
        real: "アプリが実際の送信元アドレスを受け取る",
        udpOnly: "UDP だけが実際の送信元アドレスを持つ",
        none: "アプリに渡さない",
      },
      udpDirectHint:
        "トンネルポートにあるアプリ自身のソケットへそのまま届けます。リースが有効で接続が開いている間だけで、送信元は IP ブロックリストと自動ブロックで確認されます",
      udpRelayedHint:
        "VPN Manager がローカルアドレスから中継します。アプリから見える送信元はすべてローカルアドレスです",
      udpDirect: "サンドボックスへ直接送信",
      udpRelayed: "ローカルアドレス経由で中継",
      provider: "プロバイダー",
      providerHint: "着信ポートとテストはこのアカウントを通します",
      airvpnWithoutAccount: "AirVPN（この接続は VPN Manager 内のアカウントで作成されたものではありません）",
      generic: "WireGuard：サーバー側で公開ポートをトンネルアドレスへ転送します",
    },
    dialog: {
      editTitle: (name) => `ポート転送 ${name} を編集`,
      description:
        "この接続のトンネルアドレスから転送されてきた接続を、同じ接続の管理対象アプリがこのコンピューターで待ち受けるポートへ届けます。アプリが実際にそのポートを保持している間だけ待ち受け、ほかのプログラムが受け取ることはありません。",
      create: "ポート転送を作成",
      chooseConnection: "接続を選択…",
      blocked: "この接続ではポート転送を設定できません",
      mustListen: (port) => `アプリは ${port} で待ち受ける必要があります`,
      protocol: "プロトコル",
      protocolUse: {
        tcp: "ほとんどのサービス（Web、SSH、ゲームサーバー）",
        udp: "例：DHT、音声通話、一部のゲーム",
        both: "例：BitTorrent（同じポートで TCP と UDP を受信）",
      },
      tcpOnly: "強制プロキシのアプリは TCP のみ受信できます",
      enforcedNote: (name) =>
        `「${name}」は強制プロキシ（macOS Seatbelt）を使います。受信できるのは TCP だけで、アプリは 127.0.0.1 だけで待ち受ける必要があります。すべてのアドレス（0.0.0.0）で待ち受けると約 2 秒以内に停止されます。UDP（例：BitTorrent の DHT）が必要な場合は、Linux の厳格な分離を使ってください。`,
      strict: {
        loopbackTitle: (port) => `厳格な分離のアプリは 127.0.0.1 の ${port} で待ち受ける必要があります`,
        loopbackBody:
          "アプリはこの接続とネットワークを共有しています。すべてのアドレス（0.0.0.0）で待ち受けると、転送がトンネルアドレスで受信するのと同じポートを占有してしまい、どちらも使えなくなります。",
        udpTitle: (port) => `厳格な分離のアプリはすべてのアドレスで UDP ${port} を受信する必要があります`,
        udpBody:
          "UDP はサンドボックスへ直接送られます。データグラムはトンネルアドレスに届くため、アプリは 0.0.0.0（またはトンネルアドレス）で受信する必要があります。127.0.0.1 だけでは受信できません。",
        bothTitle: (port) => `厳格な分離のアプリは ${port} を TCP は 127.0.0.1、UDP はすべてのアドレスで受信します`,
        bothBody:
          "TCP は転送が 127.0.0.1 から接続します。すべてのアドレスで TCP を待ち受けると、転送がトンネルアドレスで確保している同じポートを占有してしまいます。UDP はサンドボックスへ直接送られるため、アプリは 0.0.0.0（またはトンネルアドレス）で受信する必要があります。",
      },
      tunnelPortHint: "プロバイダーがトンネルアドレスへ転送するポート（AirVPN の Local port）",
      publicPortHint: "プロバイダー側で外部に公開されるポート。表示のみで、確認はされません",
      publicPortPlaceholder: "トンネルポートと同じ",
      app: "受信する管理対象アプリ",
      noApps: "この接続にはまだ管理対象アプリがありません。先に追加してください",
      chooseApp: "アプリを選択…",
      appPort: "アプリのポート",
      appPortHint: "アプリがこのコンピューターで待ち受けるポート",
      nameHint: (name) => `空欄の場合は「${name}」を使います`,
      maxConnections: "同時接続数の上限",
      maxConnectionsHint: "TCP 接続と UDP フローをそれぞれ数えます。1–16384",
      enabledHint:
        "接続が実行中でアプリがこのポートを保持している間、待ち受けます。無効にするとすぐに停止し、その接続も終了します。",
      proxy: "送信元アドレスをアプリに渡す（PROXY protocol v2）",
      proxyHint: (udp) =>
        `各 TCP 接続の先頭でヘッダーを送り、実際の送信元アドレスをアプリに伝えます（そうしないと、アプリから見える送信元はすべてローカルアドレスになります）。アプリが PROXY protocol v2 に対応していないと接続は失敗します。${udp === "direct" ? "UDP にはヘッダーを付けません（サンドボックスへ直接送られます。下記参照）。" : udp === "relayed" ? "UDP は通常どおり中継します。" : ""}`,
      proxyUdpOnly: "PROXY protocol は TCP 接続にだけ付けます。UDP だけを転送する場合は有効にできません。",
      udpDirect: "UDP をサンドボックスへ直接送信",
      udpDirectHint: (both) =>
        `UDP をローカルアドレス経由で中継せず、データグラムをトンネルポートにあるアプリ自身のソケットへそのまま届けます。アプリは実際の送信元アドレスを受け取り、同じポートから応答します（eMule の Kad や BitTorrent の DHT で必要）。アプリはすべてのアドレス（0.0.0.0）またはトンネルアドレスで受信する必要があり、アプリのポートはトンネルポートと同じにする必要があります。送信元は同じく IP ブロックリストと自動ブロックで確認されます。${both ? "TCP は通常どおり中継します。" : ""}`,
    },
  },
});
