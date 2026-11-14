// Text of the local access ports of a strictly isolated App: the rules a port must follow, the section of the App
// dialog that edits them, and what the inspector reports about each one. A sub-area of the Managed apps page
// (../messages.ts), kept apart for size; a .tsx: two sentences carry markup (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    title: "Local access ports",
    bind: {
      loopbackText: "127.0.0.1: only your own programs on this host (your SSH forwarding included) can connect",
      lan: "LAN",
      lanText:
        "0.0.0.0: other hosts in the allowed networks can connect too; from this host, still only your own programs are accepted",
    },
    state: {
      serving: "Relaying",
      app_stopped: "App not running",
      restart_needed: "Opens after a restart",
      unavailable: "Cannot listen",
    },
    problem: {
      notNetwork: (net: string) => `“${net}” is not a network (192.168.10.0/24, for example)`,
      prefix: (net: string) => `The prefix length of “${net}” is not valid`,
      everyAddress: "Every address (0.0.0.0/0, ::/0) cannot be allowed: list only the networks of your LAN",
      loopback: "Loopback addresses need not be listed: from this host, only your own programs are ever accepted",
      tooMany: (max: number) => `At most ${max} local access ports`,
      appPort: "The app's port must be 1024–65535",
      appPortRepeated: (port: number) => `The app's port ${port} already has a local access port`,
      hostPort: "The port on this host must be 1024–65535",
      hostPortRepeated: (port: number) => `Port ${port} on this host is used more than once`,
      hostPortGateway: (port: number, gateway: string) => `Port ${port} is already used by Gateway “${gateway}”`,
      allowEmpty:
        "Listening on the LAN needs the networks that may connect (192.168.10.0/24, for example); every other source is refused",
      tooManyNetworks: (max: number) => `At most ${max} allowed networks`,
    },
    /** `n` in the names below: the row's number, or `removedRow`. */
    editor: {
      intro:
        "A strictly isolated app is in a sandbox of its own, and its 127.0.0.1 is not this host's. Publish a port the app listens on inside the sandbox on this host, and a browser can open its interface or API. Connections are relayed to that port of the app only: they do not go through the VPN, and the app cannot use it to connect out.",
      appPort: "The app's port inside the sandbox",
      appPortOf: (n: string) => `App port of local access port ${n}`,
      hostPort: "Port on this host",
      hostPortOf: (n: string) => `Host port of local access port ${n}`,
      suggested: "Suggested automatically",
      whoCanConnect: "Who can connect",
      bindOf: (n: string) => `Listen address of local access port ${n}`,
      remove: (n: string) => `Remove local access port ${n}`,
      allow: "Networks allowed to connect (separated by commas or spaces)",
      allowOf: (n: string) => `Allowed networks of local access port ${n}`,
      urls: "Address to open",
      /** The command that forwards the port over SSH; the two placeholders name what the reader fills in. */
      sshForward: (port: number) => `ssh -L ${port}:127.0.0.1:${port} <user>@<this host>`,
      /** `ssh`: the forwarding command; `url`: the address to open afterwards. */
      fromOtherComputers: (ssh: ReactNode, url: ReactNode): ReactNode => (
        <>
          From another computer: {ssh}, then open {url}
        </>
      ),
      lanWarning:
        "Any device in the allowed networks can connect to this app, and every connection the app sees comes from 127.0.0.1: if it lets “local” connections through on that alone, these devices are let through as well.",
      full: (max: number) => `At most ${max} local access ports`,
      add: "Add local access port",
    },
    status: {
      allowed: (networks: readonly string[]) =>
        `Allowed to connect: ${networks.join(", ")}; from this host, only your own programs are accepted`,
      notListening: (port: number) =>
        `The app is not listening on 127.0.0.1:${port} inside the sandbox, so connections relayed to it fail; check the app's settings.`,
      listening: (port: number) => `The app listens on ${port} inside the sandbox (checked every 2 seconds)`,
      /** The two counters, each already an element. */
      counts: (accepted: ReactNode, refused: ReactNode): ReactNode => (
        <>
          {accepted} relayed, {refused} refused (since the core service last started)
        </>
      ),
      notReported: "The core service did not report the state of this port",
      errorAt: (message: string, when: string) => `${message} (${when})`,
      lastRefused: (message: string, when: string) => `Last refusal: ${message} (${when})`,
    },
  },
  "zh-TW": {
    title: "本機存取埠",
    bind: {
      loopbackText: "127.0.0.1：只有這台主機上你自己的程式（含你的 SSH 轉發）能連",
      lan: "區網",
      lanText: "0.0.0.0：允許的網段裡的其他主機也能連；本機的連線仍只接受你自己的程式",
    },
    state: {
      serving: "轉送中",
      app_stopped: "App 未執行",
      restart_needed: "重新啟動後開放",
      unavailable: "無法監聽",
    },
    problem: {
      notNetwork: (net) => `「${net}」不是網段（例如 192.168.10.0/24）`,
      prefix: (net) => `「${net}」的前綴長度不對`,
      everyAddress: "不能允許所有位址（0.0.0.0/0、::/0）：請只列出你的區網網段",
      loopback: "本機位址不必列出：這台主機上的程式一律只接受你自己的",
      tooMany: (max) => `本機存取埠最多 ${max} 個`,
      appPort: "App 的 port 必須是 1024–65535",
      appPortRepeated: (port) => `App 的 port ${port} 已經有本機存取埠`,
      hostPort: "本機的 port 必須是 1024–65535",
      hostPortRepeated: (port) => `本機的 port ${port} 重複使用`,
      hostPortGateway: (port, gateway) => `port ${port} 已被代理埠「${gateway}」使用`,
      allowEmpty: "在區網監聽時必須列出允許連入的網段（例如 192.168.10.0/24）；其他來源一律拒絕",
      tooManyNetworks: (max) => `允許的網段最多 ${max} 個`,
    },
    editor: {
      intro:
        "嚴格隔離的 App 在自己的 sandbox 裡，它的 127.0.0.1 不是這台主機的。把 App 在 sandbox 內監聽的 port 開到這台主機上，就能用瀏覽器打開它的介面或 API。只轉送到 App 的這個 port：不經 VPN，App 也不能藉它連出去。",
      appPort: "App 在 sandbox 內的 port",
      appPortOf: (n) => `本機存取埠 ${n} 的 App port`,
      hostPort: "這台主機的 port",
      hostPortOf: (n) => `本機存取埠 ${n} 的本機 port`,
      suggested: "自動建議",
      whoCanConnect: "誰能連",
      bindOf: (n) => `本機存取埠 ${n} 的監聽位址`,
      remove: (n) => `移除本機存取埠 ${n}`,
      allow: "允許連入的網段（以逗號或空白分隔）",
      allowOf: (n) => `本機存取埠 ${n} 允許的網段`,
      urls: "開啟網址",
      sshForward: (port) => `ssh -L ${port}:127.0.0.1:${port} <使用者>@<這台主機>`,
      fromOtherComputers: (ssh, url) => (
        <>
          從其他電腦：{ssh}，再開 {url}
        </>
      ),
      lanWarning:
        "允許的網段裡任何裝置都能連到這個 App，而 App 看到的連線都來自 127.0.0.1：它若只憑「來自本機」放行，這些裝置也會被放行。",
      full: (max) => `最多 ${max} 個本機存取埠`,
      add: "新增本機存取埠",
    },
    status: {
      allowed: (networks) => `允許連入：${networks.join("、")}；本機的連線只接受你自己的程式`,
      notListening: (port) =>
        `App 沒有在 sandbox 內的 127.0.0.1:${port} 監聽，轉送過去的連線會失敗；請確認 App 的設定。`,
      listening: (port) => `App 在 sandbox 內監聽 ${port}（每 2 秒檢查）`,
      counts: (accepted, refused) => (
        <>
          已轉送 {accepted}、已拒絕 {refused}（核心服務這次啟動以來）
        </>
      ),
      notReported: "核心服務沒有回報這個埠的狀態",
      errorAt: (message, when) => `${message}（${when}）`,
      lastRefused: (message, when) => `最近拒絕：${message}（${when}）`,
    },
  },
  ja: {
    title: "ローカルアクセスポート",
    bind: {
      loopbackText:
        "127.0.0.1：このホスト上の自分のプログラム（自分の SSH ポートフォワーディングを含む）だけが接続できます",
      lan: "LAN",
      lanText:
        "0.0.0.0：許可したネットワーク内のほかのホストも接続できます。このホストからの接続は引き続き自分のプログラムだけを受け付けます",
    },
    state: {
      serving: "中継中",
      app_stopped: "アプリ停止中",
      restart_needed: "再起動後に公開",
      unavailable: "待ち受け不可",
    },
    problem: {
      notNetwork: (net) => `「${net}」はネットワークではありません（例：192.168.10.0/24）`,
      prefix: (net) => `「${net}」のプレフィックス長が正しくありません`,
      everyAddress: "すべてのアドレス（0.0.0.0/0、::/0）は許可できません。LAN のネットワークだけを指定してください",
      loopback:
        "ループバックアドレスを指定する必要はありません。このホストからの接続は常に自分のプログラムだけを受け付けます",
      tooMany: (max) => `ローカルアクセスポートは最大 ${max} 個です`,
      appPort: "アプリのポートは 1024–65535 にしてください",
      appPortRepeated: (port) => `アプリのポート ${port} にはすでにローカルアクセスポートがあります`,
      hostPort: "このホストのポートは 1024–65535 にしてください",
      hostPortRepeated: (port) => `このホストのポート ${port} が重複しています`,
      hostPortGateway: (port, gateway) => `ポート ${port} はすでにゲートウェイ「${gateway}」が使用しています`,
      allowEmpty:
        "LAN で待ち受けるときは、接続を許可するネットワークを指定してください（例：192.168.10.0/24）。それ以外の送信元はすべて拒否されます",
      tooManyNetworks: (max) => `許可するネットワークは最大 ${max} 個です`,
    },
    editor: {
      intro:
        "厳格に分離されたアプリは専用のサンドボックスの中にあり、その 127.0.0.1 はこのホストのものではありません。アプリがサンドボックス内で待ち受けているポートをこのホストに公開すると、ブラウザーでそのインターフェースや API を開けます。中継先はアプリのこのポートだけです。VPN は経由せず、アプリがこれを使って外部に接続することもできません。",
      appPort: "サンドボックス内のアプリのポート",
      appPortOf: (n) => `ローカルアクセスポート ${n} のアプリのポート`,
      hostPort: "このホストのポート",
      hostPortOf: (n) => `ローカルアクセスポート ${n} のこのホストのポート`,
      suggested: "自動で提案",
      whoCanConnect: "接続できる相手",
      bindOf: (n) => `ローカルアクセスポート ${n} の待ち受けアドレス`,
      remove: (n) => `ローカルアクセスポート ${n} を削除`,
      allow: "接続を許可するネットワーク（カンマまたはスペース区切り）",
      allowOf: (n) => `ローカルアクセスポート ${n} で許可するネットワーク`,
      urls: "開くアドレス",
      sshForward: (port) => `ssh -L ${port}:127.0.0.1:${port} <ユーザー>@<このホスト>`,
      fromOtherComputers: (ssh, url) => (
        <>
          ほかのコンピューターから：{ssh} を実行してから {url} を開きます
        </>
      ),
      lanWarning:
        "許可したネットワーク内のどのデバイスもこのアプリに接続でき、アプリから見える接続はすべて 127.0.0.1 から来ます。アプリが「ローカルからの接続」というだけで許可しているなら、これらのデバイスも許可されます。",
      full: (max) => `ローカルアクセスポートは最大 ${max} 個です`,
      add: "ローカルアクセスポートを追加",
    },
    status: {
      allowed: (networks) =>
        `接続を許可：${networks.join("、")}。このホストからの接続は自分のプログラムだけを受け付けます`,
      notListening: (port) =>
        `アプリはサンドボックス内の 127.0.0.1:${port} で待ち受けていないため、中継した接続は失敗します。アプリの設定を確認してください。`,
      listening: (port) => `アプリはサンドボックス内で ${port} を待ち受けています（2 秒ごとに確認）`,
      counts: (accepted, refused) => (
        <>
          中継 {accepted} 件、拒否 {refused} 件（コアサービスの今回の起動以降）
        </>
      ),
      notReported: "コアサービスがこのポートの状態を報告していません",
      errorAt: (message, when) => `${message}（${when}）`,
      lastRefused: (message, when) => `最後の拒否：${message}（${when}）`,
    },
  },
});
