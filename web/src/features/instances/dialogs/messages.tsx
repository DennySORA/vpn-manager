// Text of the connection dialogs: creating and editing a connection (instance-dialog.tsx), and the confirmations
// behind 急停 and 刪除 (action-host.tsx). The list, the states and the actions are in ../messages.ts, the inspector's
// text in ../inspector/messages.tsx.

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** Shows a phrase of a sentence in its own look (emphasis, a monospace span). */
type Wrap = (text: string) => ReactNode;

/** A Chinese or Japanese phrase as a sentence of its own: ended with 。 unless it already is. */
function sentenceCjk(text: string): string {
  return text.endsWith("。") ? text : `${text}。`;
}
/** Shows a number of a sentence in its own look. */
type WrapNumber = (value: number) => ReactNode;

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** “A”, “B”, and “C”. */
function quotedEn(names: readonly string[]): string {
  return listEn.format(names.map((name) => `“${name}”`));
}

/** 「A」、「B」. */
function quotedCjk(names: readonly string[]): string {
  return names.map((name) => `「${name}」`).join("、");
}

function gatewaysEn(count: number): string {
  return count === 1 ? "Gateway" : "Gateways";
}

/** The ports of Gateways as they are written (“:1080”). */
function ports(list: readonly number[], separator: string): string {
  return list.map((port) => `:${port}`).join(separator);
}

export const m = defineMessages({
  en: {
    emergency: {
      title: (name: string) => `Emergency stop “${name}”?`,
      confirm: "Emergency stop now",
      /** `gateways`: how many Gateways the connection has. */
      body: (gateways: number, strong: Wrap): ReactNode => (
        <>
          The data path closes at once: every connection
          {gateways ? ` on its ${gateways} ${gatewaysEn(gateways)}` : ""} is cut and refused, and{" "}
          {strong("never falls back to the ordinary network")}.
        </>
      ),
      latches: "The emergency stop stays until you release it by hand; it does not lift after a reboot either.",
    },
    delete: {
      title: (name: string) => `Delete the connection “${name}”?`,
      /** `gatewayPorts`: the ports of the Gateways deleted with it. */
      body: (gatewayPorts: readonly number[]) =>
        `${
          gatewayPorts.length
            ? `Its ${gatewayPorts.length} ${gatewaysEn(gatewayPorts.length)} (${ports(gatewayPorts, ", ")}) ${gatewayPorts.length === 1 ? "is" : "are"} deleted with it.`
            : "This connection has no Gateways."
        } The WireGuard profile, DNS and security profile it uses are not affected.`,
      done: (name: string) => `Deleted connection ${name}`,
      /** What a failed deletion is reported as (the notification adds that it failed). */
      intent: (name: string) => `Delete ${name}`,
    },
    title: {
      create: "Add connection",
      edit: (name: string) => `Edit ${name}`,
    },
    description: {
      create: "A connection is an independent WireGuard exit, used through a local Gateway.",
      edit: "Changes are saved as a new version; a running connection applies them after a restart.",
    },
    submitCreate: "Create connection",
    noProfiles: {
      title: "Import a WireGuard profile first",
      import: "Import profile",
      body: "A connection uses a WireGuard profile (.conf) as its exit identity.",
    },
    /** A WireGuard profile in the list: its name and where it exits. */
    profileOption: (name: string, where: string) => `${name} (${where})`,
    fields: {
      namePlaceholder: "For example: Tokyo exit",
      profile: "WireGuard profile",
      profileHint: "The exit's identity and endpoint; one key can be used by only one running connection at a time.",
      chooseProfile: "Choose a profile…",
      dnsHint: "Every DNS query leaves through the tunnel.",
      chooseDns: "Choose a DNS profile…",
      profileDns: "DNS in the configuration file",
      security: "Security profile",
      securityHint:
        "Without one, the default security policy applies: only public internet addresses are allowed, the built-in IP blocklists apply and auto-ban is on.",
      defaultSecurity: "Default security policy",
      transport: "Transport profile",
      /** `summary`: what the chosen transport profile holds, in one sentence. */
      transportHint: (summary: string) =>
        `${summary} Applied as soon as it is saved to the connections opened from then on, without a restart.`,
      transportNone: "Each connection's buffers, timeouts and health probe.",
      transportCurrent: "The current profile (loading, or no longer exists)",
      transportAuto: "Automatic",
      mine: "My profiles",
    },
    /** Other connections that hold the same WireGuard key. */
    key: {
      inUse: (names: readonly string[]) =>
        `Used by ${quotedEn(names)}: only one connection per WireGuard key can run at a time.`,
      inUseRunning: (names: readonly string[]) =>
        `Used by ${quotedEn(names)} and running: only one connection per WireGuard key can run at a time, so this connection can start only after that one stops.`,
    },
    errors: {
      profile: "Choose a WireGuard profile",
      dns: "Choose a DNS profile",
      port: "Enter a port from 1024 to 65535",
      portTaken: (name: string) => `Already used by the Gateway “${name}”`,
    },
    /** The profile declares no DNS server. */
    dnsNotice: {
      title: "This WireGuard profile declares no DNS server",
      preset: "Create a DNS profile from a common server",
      unreachable: "Outside this profile's AllowedIPs: the tunnel cannot reach it",
      /** `haveProfiles`: DNS profiles exist to choose from. */
      needsPreset: (haveProfiles: boolean) =>
        `The connection needs a DNS profile to start: ${haveProfiles ? "choose one above, or " : ""}create one from a common server, and it is selected once created.`,
      /** `allowed`: the profile's AllowedIPs; `haveUsable`: an existing DNS profile this tunnel reaches is offered. */
      needsInner: (allowed: readonly string[], haveUsable: boolean) =>
        `The connection needs a DNS profile to start. This profile sends only ${allowed.join(", ")} into the tunnel, and the common public DNS servers are all outside it: ${haveUsable ? "use the existing DNS profile below, or enter" : "enter"} a DNS server within these ranges (such as the DNS of a company or home network).`,
      innerLabel: "DNS server inside the tunnel",
      innerPlaceholder: (example: string) => `For example ${example}`,
      useInner: "Use this DNS server",
      innerInvalid: "Needs an IP address within AllowedIPs",
    },
    /** The profile sends only private addresses into the tunnel. */
    privateNotice: {
      title: "This profile sends only private network addresses into the tunnel",
      create: "Create a security profile that allows these ranges",
      /** `security`: the chosen security profile's name (null: the default policy); `refused`: what it does not allow. */
      body: (
        mono: Wrap,
        allowed: readonly string[],
        security: string | null,
        refused: readonly string[],
      ): ReactNode => (
        <>
          AllowedIPs holds only {mono(allowed.join(", "))}
          {security !== null
            ? `; the security profile “${security}” does not allow ${refused.join(", ")}, so connections to these addresses are refused.`
            : "; the default security policy refuses private destinations, so all traffic sent through this connection is refused."}
        </>
      ),
    },
    /** Choose another existing profile in place of the selected one. */
    useInstead: (name: string) => `Use “${name}”`,
    /** The name of the security profile created to allow the private AllowedIPs of the WireGuard profile `name`. */
    allowRangesName: (name: string) => `Allow the private networks of “${name}”`,
    /** The name of the Gateway created with a new connection. */
    gatewayName: (port: number) => `Gateway ${port}`,
    extras: {
      withGateway: "Also create a Mixed Gateway",
      withGatewayNote: "Accepts both SOCKS5 and HTTP on 127.0.0.1; it can be added to or changed later.",
      port: "Gateway port",
      startNow: "Start once created",
      startNowNote: "Connections open only after the handshake and DNS verification pass.",
    },
    strict: {
      label: "Strict isolation (Linux sandbox)",
      note: "Managed apps run in a sandbox (a rootless network namespace) connected only to this tunnel; this connection's own DNS and Gateways also use the network inside the sandbox. A change takes effect after a restart.",
      checking: "Checking whether this host supports strict isolation…",
      unknown: "Cannot read the host's capabilities, so strict isolation cannot be turned on for now.",
      unsupported: "The core service did not report the strict isolation capability, so it cannot be turned on.",
    },
    limits: {
      title: "Resource limits",
      tcp: "TCP connections",
      udp: "UDP associations",
      memory: "Connection buffer (MiB)",
      /** How many proxied TCP connections the limits allow; `flows` and `mib` are kept for DNS and health probes. */
      capacity: (num: WrapNumber, limit: number, byMemory: boolean, flows: number, mib: number): ReactNode => (
        <>
          At most {num(limit)} TCP connections in practice{byMemory ? ", bound by the connection buffer" : ""} (after
          the {flows} connections and {mib} MiB kept for DNS and health probes).
        </>
      ),
      /** `tcp`, `udp`: what one TCP connection and one UDP association reserve as they open. */
      budget: (tcp: string, udp: string) =>
        `The connection buffer is the total budget for the send and receive buffers of every proxied connection: with the chosen transport profile, each TCP connection reserves ${tcp} as it opens and each UDP association ${udp}; when a fast connection grows its buffers, it uses only three quarters of the budget. When a systemd service runs it on Linux, the memory limit of the worker process is the connection buffer plus 256 MiB.`,
      download: "Download limit (Mbit/s)",
      upload: "Upload limit (Mbit/s)",
      bandwidth:
        "A limit shared by every Gateway of this connection (0.1–100000 Mbit/s; empty for none). Over the limit, TCP waits and loses no data, while UDP packets are dropped. Applied to the running connection as soon as it is saved, without a restart.",
    },
    /** The submit button's word while the new connection's Gateway is created. */
    creatingGateway: "Creating the Gateway",
    toast: {
      dnsCreated: (name: string) => `Created the DNS profile ${name}`,
      securityCreated: (name: string) => `Created the security profile ${name}`,
      selected: "Selected for this connection.",
      created: (name: string) => `Created the connection ${name}`,
      createdGateway: (port: number) => `Gateway 127.0.0.1:${port}`,
      updated: (name: string) => `Updated ${name}`,
      updatedRestart: "The running connection applies the new settings after a restart.",
    },
    /** What was attempted, for the report of a failure: the notification adds that it failed. */
    intent: {
      dns: (name: string) => `Create the DNS profile ${name}`,
      security: (name: string) => `Create the security profile ${name}`,
      gateway: "Create the Gateway",
    },
  },
  "zh-TW": {
    emergency: {
      title: (name) => `急停「${name}」？`,
      confirm: "立即急停",
      body: (gateways, strong) => (
        <>
          立刻封閉資料路徑：{gateways ? `${gateways} 個代理埠上的` : ""}所有連線都會中斷並被拒絕，
          {strong("不會改走一般網路")}。
        </>
      ),
      latches: "急停會一直保持，直到你手動解除；重新開機後也不會自動恢復。",
    },
    delete: {
      title: (name) => `刪除連線「${name}」？`,
      body: (gatewayPorts) =>
        `${
          gatewayPorts.length
            ? `它的 ${gatewayPorts.length} 個代理埠（${ports(gatewayPorts, "、")}）會一起刪除。`
            : "這條連線沒有代理埠。"
        }使用的 WireGuard 設定、DNS 與安全設定不受影響。`,
      done: (name) => `已刪除連線 ${name}`,
      intent: (name) => `刪除 ${name}`,
    },
    title: {
      create: "新增連線",
      edit: (name) => `編輯 ${name}`,
    },
    description: {
      create: "一條連線是一個獨立的 WireGuard 出口，透過本機代理埠使用。",
      edit: "變更會保存為新版本；執行中的連線在重新啟動後套用。",
    },
    submitCreate: "建立連線",
    noProfiles: {
      title: "需要先匯入 WireGuard 設定",
      import: "匯入設定",
      body: "連線使用一份 WireGuard 設定（.conf）作為出口身分。",
    },
    profileOption: (name, where) => `${name}（${where}）`,
    fields: {
      namePlaceholder: "例如：東京出口",
      profile: "WireGuard 設定",
      profileHint: "出口的身分與端點；同一把金鑰同時只能被一條執行中的連線使用。",
      chooseProfile: "選擇設定…",
      dnsHint: "所有 DNS 查詢都經 tunnel 送出。",
      chooseDns: "選擇 DNS 設定…",
      profileDns: "設定檔宣告的 DNS",
      security: "安全設定",
      securityHint: "未選擇時使用預設安全政策：只允許公開網際網路位址，套用內建 IP 封鎖清單並開啟自動封鎖。",
      defaultSecurity: "預設安全政策",
      transport: "傳輸設定",
      transportHint: (summary) => `${sentenceCjk(summary)}儲存後立即套用到之後建立的連線，不需要重新啟動。`,
      transportNone: "每條連線的緩衝、逾時與健康探測。",
      transportCurrent: "目前的設定（載入中或已不存在）",
      transportAuto: "自動",
      mine: "我的設定",
    },
    key: {
      inUse: (names) => `已被${quotedCjk(names)}使用：同一把 WireGuard 金鑰同一時間只能有一條連線在執行。`,
      inUseRunning: (names) =>
        `已被${quotedCjk(names)}使用且正在執行：同一把 WireGuard 金鑰同一時間只能有一條連線在執行，這條連線要等它停止後才能啟動。`,
    },
    errors: {
      profile: "請選擇 WireGuard 設定",
      dns: "請選擇 DNS 設定",
      port: "請輸入 1024–65535 之間的埠號",
      portTaken: (name) => `已被代理埠「${name}」使用`,
    },
    dnsNotice: {
      title: "這份 WireGuard 設定沒有宣告 DNS 伺服器",
      preset: "用常用伺服器建立 DNS 設定",
      unreachable: "不在這份設定的 AllowedIPs 內，tunnel 送不到",
      needsPreset: (haveProfiles) =>
        `連線需要一份 DNS 設定才能啟動：${haveProfiles ? "在上方選擇一份，或" : ""}用常用伺服器建立一份，建立後直接選用。`,
      needsInner: (allowed, haveUsable) =>
        `連線需要一份 DNS 設定才能啟動。這份設定只把 ${allowed.join("、")} 送進 tunnel，常用的公開 DNS 都在範圍外：${haveUsable ? "改用下面這份已有的 DNS 設定，或" : "請"}輸入這些網段內的 DNS 伺服器（例如公司或家用網路自己的 DNS）。`,
      innerLabel: "tunnel 內的 DNS 伺服器",
      innerPlaceholder: (example) => `例如 ${example}`,
      useInner: "使用這台 DNS",
      innerInvalid: "需要 AllowedIPs 內的 IP 位址",
    },
    privateNotice: {
      title: "這份設定只把私網位址送進 tunnel",
      create: "建立允許這些網段的安全設定",
      body: (mono, allowed, security, refused) => (
        <>
          AllowedIPs 只有 {mono(allowed.join("、"))}
          {security !== null
            ? `；安全設定「${security}」沒有允許 ${refused.join("、")}，到這些位址的連線會被拒絕。`
            : "；預設安全政策拒絕私網目的地，所以經這條連線送出的流量都會被拒絕。"}
        </>
      ),
    },
    useInstead: (name) => `改用「${name}」`,
    allowRangesName: (name) => `允許「${name}」的私網`,
    gatewayName: (port) => `代理埠 ${port}`,
    extras: {
      withGateway: "同時建立 Mixed 代理埠",
      withGatewayNote: "在 127.0.0.1 上同時接受 SOCKS5 與 HTTP；之後可再新增或修改。",
      port: "代理埠埠號",
      startNow: "建立後立即啟動",
      startNowNote: "握手與 DNS 驗證通過後才會開放連線。",
    },
    strict: {
      label: "嚴格隔離（Linux 沙箱）",
      note: "受管 App 在只連到這條 tunnel 的沙箱（rootless network namespace）中執行；這條連線自己的 DNS 與代理埠也改走沙箱內的網路。變更在重新啟動後生效。",
      checking: "正在確認這台主機是否支援嚴格隔離…",
      unknown: "無法取得主機能力，暫時不能開啟嚴格隔離。",
      unsupported: "核心服務沒有回報嚴格隔離能力，不能開啟。",
    },
    limits: {
      title: "資源上限",
      tcp: "TCP 連線",
      udp: "UDP 關聯",
      memory: "連線緩衝（MiB）",
      capacity: (num, limit, byMemory, flows, mib) => (
        <>
          TCP 連線實際最多 {num(limit)} 條{byMemory ? "，受連線緩衝限制" : ""}（已扣除保留給 DNS 與健康探測的 {flows}{" "}
          條與 {mib} MiB）。
        </>
      ),
      budget: (tcp, udp) =>
        `連線緩衝是所有代理連線收發緩衝的總預算：依選用的傳輸設定，每條 TCP 連線建立時預留 ${tcp}、每個 UDP 關聯 ${udp}；傳得快的連線再放大緩衝時，只用預算的四分之三。在 Linux 由 systemd 服務執行時，worker 程序的記憶體上限是連線緩衝再加 256 MiB。`,
      download: "下載上限（Mbit/s）",
      upload: "上傳上限（Mbit/s）",
      bandwidth:
        "這條連線所有代理埠共用的上限（0.1–100000 Mbit/s，留空不限）。TCP 超過上限時等待，不丟資料；超過上限的 UDP 封包會被丟棄。儲存後立即套用到執行中的連線，不需要重新啟動。",
    },
    creatingGateway: "建立代理埠",
    toast: {
      dnsCreated: (name) => `已建立 DNS 設定 ${name}`,
      securityCreated: (name) => `已建立安全設定 ${name}`,
      selected: "已為這條連線選用。",
      created: (name) => `已建立連線 ${name}`,
      createdGateway: (port) => `代理埠 127.0.0.1:${port}`,
      updated: (name) => `已更新 ${name}`,
      updatedRestart: "執行中的連線會在重新啟動後套用新設定。",
    },
    intent: {
      dns: (name) => `建立 DNS 設定 ${name}`,
      security: (name) => `建立安全設定 ${name}`,
      gateway: "建立代理埠",
    },
  },
  ja: {
    emergency: {
      title: (name) => `「${name}」を緊急停止しますか？`,
      confirm: "今すぐ緊急停止",
      body: (gateways, strong) => (
        <>
          データ経路をただちに閉じます。{gateways ? `${gateways} 個のゲートウェイの` : ""}
          すべての接続が切断・拒否され、{strong("通常のネットワークには切り替わりません")}。
        </>
      ),
      latches: "緊急停止は手動で解除するまで続きます。再起動しても自動では解除されません。",
    },
    delete: {
      title: (name) => `接続「${name}」を削除しますか？`,
      body: (gatewayPorts) =>
        `${
          gatewayPorts.length
            ? `${gatewayPorts.length} 個のゲートウェイ（${ports(gatewayPorts, "、")}）も一緒に削除されます。`
            : "この接続にはゲートウェイがありません。"
        }使用している WireGuard 設定、DNS、セキュリティ設定には影響しません。`,
      done: (name) => `接続 ${name} を削除しました`,
      intent: (name) => `${name} の削除`,
    },
    title: {
      create: "接続を追加",
      edit: (name) => `${name} を編集`,
    },
    description: {
      create: "接続はそれぞれ独立した WireGuard 出口で、ローカルのゲートウェイ経由で使います。",
      edit: "変更は新しいバージョンとして保存されます。実行中の接続には再起動後に適用されます。",
    },
    submitCreate: "接続を作成",
    noProfiles: {
      title: "先に WireGuard 設定をインポートしてください",
      import: "設定をインポート",
      body: "接続は WireGuard 設定（.conf）を出口の ID として使います。",
    },
    profileOption: (name, where) => `${name}（${where}）`,
    fields: {
      namePlaceholder: "例：東京の出口",
      profile: "WireGuard 設定",
      profileHint: "出口の ID とエンドポイント。1 つの鍵を同時に使える実行中の接続は 1 つだけです。",
      chooseProfile: "設定を選択…",
      dnsHint: "DNS の問い合わせはすべてトンネル経由で送信されます。",
      chooseDns: "DNS 設定を選択…",
      profileDns: "設定ファイルの DNS",
      security: "セキュリティ設定",
      securityHint:
        "選択しない場合は既定のセキュリティポリシーを使います：公開インターネットのアドレスだけを許可し、組み込みの IP ブロックリストを適用して、自動ブロックを有効にします。",
      defaultSecurity: "既定のセキュリティポリシー",
      transport: "トランスポート設定",
      transportHint: (summary) =>
        `${sentenceCjk(summary)}保存するとすぐに、その後に開く接続に適用されます。再起動は不要です。`,
      transportNone: "接続ごとのバッファー、タイムアウト、ヘルスチェック。",
      transportCurrent: "現在の設定（読み込み中、または存在しません）",
      transportAuto: "自動",
      mine: "自分の設定",
    },
    key: {
      inUse: (names) => `${quotedCjk(names)}が使用中です：同じ WireGuard 鍵で同時に実行できる接続は 1 つだけです。`,
      inUseRunning: (names) =>
        `${quotedCjk(names)}がこの設定で実行中です。同じ WireGuard 鍵で同時に実行できる接続は 1 つだけのため、この接続はそちらが停止してから開始できます。`,
    },
    errors: {
      profile: "WireGuard 設定を選択してください",
      dns: "DNS 設定を選択してください",
      port: "1024–65535 のポート番号を入力してください",
      portTaken: (name) => `ゲートウェイ「${name}」が使用中です`,
    },
    dnsNotice: {
      title: "この WireGuard 設定は DNS サーバーを宣言していません",
      preset: "よく使われるサーバーで DNS 設定を作成",
      unreachable: "この設定の AllowedIPs の範囲外のため、トンネルで届きません",
      needsPreset: (haveProfiles) =>
        `接続を開始するには DNS 設定が必要です：${haveProfiles ? "上で選択するか、" : ""}よく使われるサーバーで作成してください。作成するとそのまま選択されます。`,
      needsInner: (allowed, haveUsable) =>
        `接続を開始するには DNS 設定が必要です。この設定がトンネルに送るのは ${allowed.join("、")} だけで、よく使われる公開 DNS はすべて範囲外です：${haveUsable ? "下の既存の DNS 設定を使うか、" : ""}これらのネットワーク内の DNS サーバー（会社や家庭のネットワーク独自の DNS など）を入力してください。`,
      innerLabel: "トンネル内の DNS サーバー",
      innerPlaceholder: (example) => `例：${example}`,
      useInner: "この DNS を使用",
      innerInvalid: "AllowedIPs 内の IP アドレスが必要です",
    },
    privateNotice: {
      title: "この設定がトンネルに送るのはプライベートネットワークのアドレスだけです",
      create: "これらのネットワークを許可するセキュリティ設定を作成",
      body: (mono, allowed, security, refused) => (
        <>
          AllowedIPs は {mono(allowed.join("、"))} だけです
          {security !== null
            ? `。セキュリティ設定「${security}」は ${refused.join("、")} を許可していないため、これらのアドレスへの接続は拒否されます。`
            : "。既定のセキュリティポリシーはプライベートネットワーク宛ての通信を拒否するため、この接続経由で送信されるトラフィックはすべて拒否されます。"}
        </>
      ),
    },
    useInstead: (name) => `「${name}」を使用`,
    allowRangesName: (name) => `「${name}」のプライベートネットワークを許可`,
    gatewayName: (port) => `ゲートウェイ ${port}`,
    extras: {
      withGateway: "Mixed ゲートウェイも作成",
      withGatewayNote: "127.0.0.1 で SOCKS5 と HTTP の両方を受け付けます。あとから追加や変更もできます。",
      port: "ゲートウェイのポート番号",
      startNow: "作成後すぐに開始",
      startNowNote: "ハンドシェイクと DNS の検証に合格してから、接続を受け付けます。",
    },
    strict: {
      label: "厳格な分離（Linux サンドボックス）",
      note: "管理対象アプリは、このトンネルだけにつながるサンドボックス（rootless network namespace）の中で実行されます。この接続自身の DNS とゲートウェイも、サンドボックス内のネットワークを使います。変更は再起動後に有効になります。",
      checking: "このホストが厳格な分離に対応しているか確認しています…",
      unknown: "ホストの機能を取得できないため、現在は厳格な分離を有効にできません。",
      unsupported: "コアサービスが厳格な分離の機能を報告していないため、有効にできません。",
    },
    limits: {
      title: "リソースの上限",
      tcp: "TCP 接続",
      udp: "UDP アソシエーション",
      memory: "接続バッファー（MiB）",
      capacity: (num, limit, byMemory, flows, mib) => (
        <>
          DNS とヘルスチェック用に確保する {flows} 本と {mib} MiB を除き、TCP 接続は実際には最大 {num(limit)} 本です
          {byMemory ? "（接続バッファーによる制限）" : ""}。
        </>
      ),
      budget: (tcp, udp) =>
        `接続バッファーは、すべてのプロキシ接続の送受信バッファーの合計予算です。選択したトランスポート設定に従い、TCP 接続は開くときに ${tcp}、UDP アソシエーションは ${udp} をそれぞれ確保します。高速な接続がバッファーを拡大するときは、予算の 4 分の 3 までしか使いません。Linux で systemd サービスとして実行する場合、worker プロセスのメモリ上限は接続バッファーに 256 MiB を加えた値です。`,
      download: "ダウンロードの上限（Mbit/s）",
      upload: "アップロードの上限（Mbit/s）",
      bandwidth:
        "この接続のすべてのゲートウェイで共有する上限です（0.1–100000 Mbit/s、空欄で無制限）。上限を超えると TCP は待機してデータを失いませんが、UDP パケットは破棄されます。保存するとすぐに実行中の接続に適用され、再起動は不要です。",
    },
    creatingGateway: "ゲートウェイを作成中",
    toast: {
      dnsCreated: (name) => `DNS 設定 ${name} を作成しました`,
      securityCreated: (name) => `セキュリティ設定 ${name} を作成しました`,
      selected: "この接続に選択しました。",
      created: (name) => `接続 ${name} を作成しました`,
      createdGateway: (port) => `ゲートウェイ 127.0.0.1:${port}`,
      updated: (name) => `${name} を更新しました`,
      updatedRestart: "実行中の接続には、再起動後に新しい設定が適用されます。",
    },
    intent: {
      dns: (name) => `DNS 設定 ${name} の作成`,
      security: (name) => `セキュリティ設定 ${name} の作成`,
      gateway: "ゲートウェイの作成",
    },
  },
});
