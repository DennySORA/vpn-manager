// Text of creating a connection from a provider account: the dialog, the exit and the entry (the route picker), the
// server list, how an entry is named and where a server is (the exit check and AirVPN's port test say it the same
// way). 出口 is where traffic leaves the provider's network, 入口 where the tunnel goes in; 多跳 (multihop) is an entry
// at another server than the exit.

import { defineMessages } from "@/i18n";

const SETUP_EN =
  "the profile, the connection and the Gateway are created in one go, and provider requests leave only through the Provider egress.";
const SETUP_ZH = "設定、連線與代理埠一次建立，供應商請求只經 Provider 出口送出。";
const SETUP_JA =
  "設定、接続、ゲートウェイをまとめて作成し、プロバイダーへのリクエストは Provider 出口だけを通って送信されます。";

export const m = defineMessages({
  en: {
    /** Where a server is, from what is known of it: 「東京，日本」, or the one part known. */
    cityAndCountry: (city: string | null, country: string | null) => [city, country].filter(Boolean).join(", "),
    /** The group of the servers whose city the provider did not state. */
    unknownCity: "City not stated",
    entry: {
      /** An AirVPN entry: its Entry IP `index` (counted from 1, as AirVPN names them) on that port. */
      address: (index: number, port: number) => `Address ${index} · UDP ${port}`,
      /** A Mullvad entry relay and its city: 「se-got-wg-001（哥特堡）」. */
      relayInCity: (server: string, city: string) => `${server} (${city})`,
    },
    dialog: {
      title: (account: string) => `Create a connection from “${account}”`,
      /** What the dialog asks for, by how the provider lets a connection choose its entry. */
      description: {
        multihop: (provider: string) =>
          `Pick ${provider}'s exit and entry servers (multihop is possible) and a device; ${SETUP_EN}`,
        entries: (provider: string) => `Pick one ${provider} server, its entry address and a device; ${SETUP_EN}`,
        single: (provider: string) => `Pick one ${provider} server and a device; ${SETUP_EN}`,
      },
      serversNeedEgress:
        "The server list is read through the Provider egress; deal with the egress state at the top of the page first.",
      serversUnreadable: "Cannot get the server list",
      loadingServers: "Reading the server list through the Provider egress",
      becomesEgress: "This connection becomes the Provider egress",
      becomesEgressHint:
        "Only one connection is created during a direct connection: it connects as soon as it is created, and the direct connection ends once it is up.",
      deviceLegend: "Device (WireGuard key)",
      device: "Device",
      newDevice: "New device",
      newDeviceAtLimit: (count: number, limit: number, canReuse: boolean) =>
        `There are already ${count} devices (the limit is ${limit}): revoke a device that is no longer used in the “Devices” list first${canReuse ? ", or reuse one of the devices on this computer listed below" : ""}; no device is ever deleted automatically.`,
      /** `count` is null while the devices are still being read. */
      newDeviceHint: (count: number | null, limit: number) =>
        `The key is generated on this computer and only the public key is sent to Mullvad (${count ?? "…"} of ${limit} devices now).`,
      reuseDevice: (label: string) => `Reuse ${label}`,
      deviceUsedBy: (names: readonly string[]) =>
        `Already used by ${names.join(", ")}; one key can serve only one running connection at a time.`,
      noAirvpnDevice: "This AirVPN account has no devices yet",
      noAirvpnDeviceHint: "Create a device in the Client Area of AirVPN's website first, then press “Refresh account”.",
      form: "Connection",
      namePlaceholder: "Filled in once a server is chosen",
      entryFamily: "IP version of the entry",
      entryFamilyLabel: "IP version of the WireGuard entry",
      multihopIpv4Only: "Multihop goes over IPv4 only",
      withGateway: "Also open a local Gateway (SOCKS5 + HTTP)",
      withGatewayHint: "Lets a browser or a tool use the network through this connection; on 127.0.0.1 only.",
      gatewayPort: "Gateway port",
      gatewayPortInUse: "Another Gateway already uses this port",
      startNow: "Connect as soon as it is created",
      startNowDirect:
        "This connection becomes the Provider egress: it connects as soon as it is created, and the direct connection ends once it is up. One direct connection creates one connection only.",
      /** Why the connection cannot be created yet. */
      reason: {
        noEgress: "Reading the servers needs a usable Provider egress",
        noExit: "Choose an exit server first",
        noEntry: "Choose an entry server first",
        deviceLimit: (limit: number) =>
          `The device limit (${limit}) is reached: revoke a device that is no longer used first, or reuse a device on this computer`,
        noDevice: "This account has no usable device yet",
        gatewayPort: (error: string) => `Gateway port: ${error}`,
      },
      view: "View connection",
      reused: "Reusing the connection this direct connection already created",
      reusedDetail:
        "One direct connection creates one connection only: it was restarted, and no new device, key or connection was made; once it is up it becomes the Provider egress.",
      created: (name: string) => `“${name}” was created`,
      createdDetail: (started: boolean, becomesEgress: boolean) =>
        `${started ? "It is connecting; its state updates live on the “Connections” page." : "It is not started yet; you can start it on the “Connections” page."}${becomesEgress ? " Once it is up it becomes the Provider egress by itself and the direct connection ends." : ""}`,
    },
    route: {
      exit: "Exit",
      exitHint: "Traffic leaves the provider's network at this server (websites see its IP)",
      exitServer: "Exit server",
      entry: "Entry",
      entryServer: "Entry server",
      sameAsExit: "Same as the exit",
      anotherServer: "Another server (multihop)",
      multihopHint:
        "The connection goes to the entry server first and on to the exit server inside Mullvad; over IPv4 only. An observer at the entry server's end can tell from the port number which server the exit is (as Mullvad explains).",
      isTheExit: "This is the exit: choose “Same as the exit”",
      noMultihop: "This exit server cannot do multihop right now",
      noMultihopHint:
        "Mullvad's server list does not confirm its multihop port; pick another exit, or choose “Same as the exit”.",
      airvpnEntryHint:
        "AirVPN has no multihop: the entry and the exit are the same server (address n is AirVPN's Entry IP n)",
      entryAddresses: "Entry address and port",
      /** `family` is “IPv4” or “IPv6”. */
      noAddress: (family: string) => `This entry has no ${family} address`,
      defaultEntry: "Default",
      current: "Current",
      oneEntryOnly: "This server has one entry only.",
      chooseExitFirst: "Choose the exit server first; the entry is one of its own addresses and ports.",
      chooseEntry: "(choose an entry server)",
      /** Read between the entry and the exit of the summary, where an arrow is drawn. */
      to: "to",
      sameServerWithIp: (ip: string) => `Same server; exit IP ${ip} (from AirVPN's list)`,
      sameServer: "Same server; confirm the exit IP with “Check exit IP” once it is connected",
      twoServers: "Two servers; the exit IP is the exit server's; confirm it with “Check exit IP” once it is connected",
      afterEntryChosen:
        "Once an entry server is chosen, the connection goes to it first and on to the exit inside Mullvad",
    },
    servers: {
      /** The name of a server list that was given none. */
      label: "Server",
      /** The search field of the list named `label` (“Exit server search”). */
      search: (label: string) => `${label} search`,
      searchPlaceholder: "Search by country, city or server name",
      count: (count: number) => `${count} ${count === 1 ? "server" : "servers"}`,
      providerOwned: "Provider-owned",
      inactive: "Inactive",
      cannotPick: "Cannot be picked",
      noMatch: (query: string) => `No server matches “${query}”`,
      matching: (count: number) =>
        `${count} ${count === 1 ? "server matches" : "servers match"}; the list comes straight from the provider.`,
      total: (count: number) =>
        `${count} ${count === 1 ? "server" : "servers"} in all; the list comes straight from the provider.`,
    },
  },
  "zh-TW": {
    /** 「城市，國家」 */
    cityAndCountry: (city, country) => [city, country].filter(Boolean).join("，"),
    unknownCity: "未標示城市",
    entry: {
      address: (index, port) => `位址 ${index} · UDP ${port}`,
      relayInCity: (server, city) => `${server}（${city}）`,
    },
    dialog: {
      title: (account) => `用「${account}」建立連線`,
      description: {
        multihop: (provider) => `挑 ${provider} 的出口與入口伺服器（可多跳）、一個裝置；${SETUP_ZH}`,
        entries: (provider) => `挑一台 ${provider} 伺服器與它的入口位址、一個裝置；${SETUP_ZH}`,
        single: (provider) => `挑一台 ${provider} 伺服器、一個裝置；${SETUP_ZH}`,
      },
      serversNeedEgress: "讀取伺服器清單需要經 Provider 出口；請先處理頁面上方的出口狀態。",
      serversUnreadable: "無法取得伺服器清單",
      loadingServers: "正在經 Provider 出口讀取伺服器清單",
      becomesEgress: "這條連線會成為 Provider 出口",
      becomesEgressHint: "直連期間只建立一條連線：它建立後立即連線，連上後直連隨即結束。",
      deviceLegend: "裝置（WireGuard 金鑰）",
      device: "裝置",
      newDevice: "新裝置",
      newDeviceAtLimit: (count, limit, canReuse) =>
        `已有 ${count} 個裝置（上限 ${limit}）：先在「裝置」清單撤銷不再使用的裝置${canReuse ? "，或沿用下列這台電腦上的裝置" : ""}；不會自動刪除任何裝置。`,
      newDeviceHint: (count, limit) =>
        `在這台電腦產生金鑰，只把公鑰送給 Mullvad（目前 ${count ?? "…"} / ${limit} 個裝置）。`,
      reuseDevice: (label) => `沿用 ${label}`,
      deviceUsedBy: (names) => `已用於 ${names.join("、")}；同一把金鑰同一時間只能有一條連線在執行。`,
      noAirvpnDevice: "這個 AirVPN 帳號還沒有裝置",
      noAirvpnDeviceHint: "請先在 AirVPN 網站的 Client Area 建立裝置，再按「重新讀取帳號」。",
      form: "連線",
      namePlaceholder: "選擇伺服器後自動產生",
      entryFamily: "入口的 IP 版本",
      entryFamilyLabel: "WireGuard 入口的 IP 版本",
      multihopIpv4Only: "多跳只走 IPv4",
      withGateway: "同時開啟本機代理埠（SOCKS5 + HTTP）",
      withGatewayHint: "讓瀏覽器或工具經這條連線上網；只在 127.0.0.1。",
      gatewayPort: "代理埠",
      gatewayPortInUse: "這個埠已被其他代理埠使用",
      startNow: "建立後立即連線",
      startNowDirect: "這條連線會成為 Provider 出口：建立後立即連線，連上後直連隨即結束。一次直連只建立一條連線。",
      reason: {
        noEgress: "需要可用的 Provider 出口才能讀取伺服器",
        noExit: "先選擇出口伺服器",
        noEntry: "先選擇入口伺服器",
        deviceLimit: (limit) => `裝置已達上限（${limit} 個）：先撤銷不再使用的裝置，或沿用這台電腦上的裝置`,
        noDevice: "這個帳號還沒有可用的裝置",
        gatewayPort: (error) => `代理埠：${error}`,
      },
      view: "查看連線",
      reused: "沿用這次直連已建立的連線",
      reusedDetail:
        "一次直連只建立一條連線：已重新啟動它，沒有建立新的裝置、金鑰或連線；它連上後會成為 Provider 出口。",
      created: (name) => `已建立「${name}」`,
      createdDetail: (started, becomesEgress) =>
        `${started ? "正在連線；狀態會在「連線」頁即時更新。" : "尚未啟動，可以在「連線」頁啟動。"}${becomesEgress ? "它連上後會自動成為 Provider 出口，直連隨即結束。" : ""}`,
    },
    route: {
      exit: "出口",
      exitHint: "流量從這台伺服器離開供應商的網路（網站看到它的 IP）",
      exitServer: "出口伺服器",
      entry: "入口",
      entryServer: "入口伺服器",
      sameAsExit: "與出口相同",
      anotherServer: "另一台（多跳）",
      multihopHint:
        "連線先到入口伺服器，再經 Mullvad 內部轉到出口伺服器；只經 IPv4。入口伺服器那一端的觀察者可以從埠號看出出口是哪一台（Mullvad 的說明）。",
      isTheExit: "這就是出口：選「與出口相同」",
      noMultihop: "這台出口伺服器現在不能多跳",
      noMultihopHint: "Mullvad 的伺服器清單沒有確認它的多跳埠；換一台出口，或選「與出口相同」。",
      airvpnEntryHint: "AirVPN 沒有多跳：入口與出口是同一台伺服器（位址 n 即 AirVPN 的 Entry IP n）",
      entryAddresses: "入口位址與埠",
      noAddress: (family) => `這個入口沒有 ${family} 位址`,
      defaultEntry: "預設",
      current: "目前",
      oneEntryOnly: "這台伺服器只有一個入口。",
      chooseExitFirst: "先選出口伺服器；入口是它自己的位址與埠。",
      chooseEntry: "（選擇入口伺服器）",
      to: "到",
      sameServerWithIp: (ip) => `同一台伺服器；出口 IP ${ip}（AirVPN 清單）`,
      sameServer: "同一台伺服器；出口 IP 連線後以「檢查出口 IP」確認",
      twoServers: "兩台伺服器；出口 IP 是出口伺服器的，連線後以「檢查出口 IP」確認",
      afterEntryChosen: "選好入口伺服器後，連線先到它，再經 Mullvad 內部轉到出口",
    },
    servers: {
      label: "伺服器",
      search: (label) => `搜尋${label}`,
      searchPlaceholder: "搜尋國家、城市或伺服器名稱",
      count: (count) => `${count} 台`,
      providerOwned: "自有機房",
      inactive: "停用",
      cannotPick: "不能選",
      noMatch: (query) => `沒有符合「${query}」的伺服器`,
      matching: (count) => `符合 ${count} 台，清單直接取自供應商。`,
      total: (count) => `共 ${count} 台，清單直接取自供應商。`,
    },
  },
  ja: {
    cityAndCountry: (city, country) => [city, country].filter(Boolean).join("、"),
    unknownCity: "都市の記載なし",
    entry: {
      address: (index, port) => `アドレス ${index} · UDP ${port}`,
      relayInCity: (server, city) => `${server}（${city}）`,
    },
    dialog: {
      title: (account) => `「${account}」で接続を作成`,
      description: {
        multihop: (provider) =>
          `${provider} の出口サーバーと入口サーバー（マルチホップ可）、デバイスを 1 つ選びます。${SETUP_JA}`,
        entries: (provider) => `${provider} のサーバーを 1 台とその入口アドレス、デバイスを 1 つ選びます。${SETUP_JA}`,
        single: (provider) => `${provider} のサーバーを 1 台とデバイスを 1 つ選びます。${SETUP_JA}`,
      },
      serversNeedEgress:
        "サーバー一覧の読み込みは Provider 出口を通ります。先にページ上部の出口の状態に対処してください。",
      serversUnreadable: "サーバー一覧を取得できません",
      loadingServers: "Provider 出口経由でサーバー一覧を読み込み中",
      becomesEgress: "この接続が Provider 出口になります",
      becomesEgressHint:
        "直接接続中に作成できる接続は 1 つだけです。作成後すぐに接続を開始し、接続が確立すると直接接続はすぐに終了します。",
      deviceLegend: "デバイス（WireGuard 鍵）",
      device: "デバイス",
      newDevice: "新しいデバイス",
      newDeviceAtLimit: (count, limit, canReuse) =>
        `すでに ${count} 台のデバイスがあります（上限 ${limit}）：${canReuse ? "先に「デバイス」一覧で使わなくなったデバイスを失効させるか、下にあるこのコンピューター上のデバイスを再利用してください" : "先に「デバイス」一覧で使わなくなったデバイスを失効させてください"}。デバイスが自動的に削除されることはありません。`,
      newDeviceHint: (count, limit) =>
        `このコンピューターで鍵を生成し、公開鍵だけを Mullvad に送ります（現在 ${count ?? "…"} / ${limit} 台）。`,
      reuseDevice: (label) => `${label} を再利用`,
      deviceUsedBy: (names) => `${names.join("、")} で使用中です。同じ鍵で同時に実行できる接続は 1 つだけです。`,
      noAirvpnDevice: "この AirVPN アカウントにはまだデバイスがありません",
      noAirvpnDeviceHint:
        "先に AirVPN の Web サイトの Client Area でデバイスを作成し、「アカウントを再読み込み」を押してください。",
      form: "接続",
      namePlaceholder: "サーバーを選ぶと自動で入力されます",
      entryFamily: "入口の IP バージョン",
      entryFamilyLabel: "WireGuard 入口の IP バージョン",
      multihopIpv4Only: "マルチホップは IPv4 のみ",
      withGateway: "ローカルのゲートウェイも開く（SOCKS5 + HTTP）",
      withGatewayHint: "ブラウザーやツールがこの接続経由で通信できるようにします。127.0.0.1 のみ。",
      gatewayPort: "ゲートウェイのポート",
      gatewayPortInUse: "このポートは別のゲートウェイが使用しています",
      startNow: "作成後すぐに接続",
      startNowDirect:
        "この接続が Provider 出口になります。作成後すぐに接続を開始し、接続が確立すると直接接続はすぐに終了します。1 回の直接接続で作成できる接続は 1 つだけです。",
      reason: {
        noEgress: "サーバーを読み込むには、利用できる Provider 出口が必要です",
        noExit: "先に出口サーバーを選んでください",
        noEntry: "先に入口サーバーを選んでください",
        deviceLimit: (limit) =>
          `デバイス数が上限（${limit} 台）に達しています：使わなくなったデバイスを先に失効させるか、このコンピューター上のデバイスを再利用してください`,
        noDevice: "このアカウントには利用できるデバイスがまだありません",
        gatewayPort: (error) => `ゲートウェイのポート：${error}`,
      },
      view: "接続を表示",
      reused: "この直接接続で作成済みの接続を再利用します",
      reusedDetail:
        "1 回の直接接続で作成できる接続は 1 つだけです。その接続を再起動し、新しいデバイス、鍵、接続は作成していません。接続が確立すると Provider 出口になります。",
      created: (name) => `「${name}」を作成しました`,
      createdDetail: (started, becomesEgress) =>
        `${started ? "接続中です。状態は「接続」ページでリアルタイムに更新されます。" : "まだ開始していません。「接続」ページで開始できます。"}${becomesEgress ? "接続が確立すると自動的に Provider 出口になり、直接接続はすぐに終了します。" : ""}`,
    },
    route: {
      exit: "出口",
      exitHint:
        "トラフィックはこのサーバーからプロバイダーのネットワークを出ます（Web サイトにはこのサーバーの IP が見えます）",
      exitServer: "出口サーバー",
      entry: "入口",
      entryServer: "入口サーバー",
      sameAsExit: "出口と同じ",
      anotherServer: "別のサーバー（マルチホップ）",
      multihopHint:
        "接続はまず入口サーバーに届き、Mullvad の内部を通って出口サーバーへ転送されます。IPv4 のみです。入口サーバー側の観察者は、ポート番号から出口がどのサーバーかを判別できます（Mullvad の説明による）。",
      isTheExit: "これは出口です：「出口と同じ」を選んでください",
      noMultihop: "この出口サーバーは現在マルチホップできません",
      noMultihopHint:
        "Mullvad のサーバー一覧で、このサーバーのマルチホップ用ポートが確認できません。別の出口を選ぶか、「出口と同じ」を選んでください。",
      airvpnEntryHint:
        "AirVPN にマルチホップはありません：入口と出口は同じサーバーです（アドレス n は AirVPN の Entry IP n）",
      entryAddresses: "入口のアドレスとポート",
      noAddress: (family) => `この入口には ${family} アドレスがありません`,
      defaultEntry: "既定",
      current: "現在",
      oneEntryOnly: "このサーバーの入口は 1 つだけです。",
      chooseExitFirst: "先に出口サーバーを選んでください。入口はそのサーバー自身のアドレスとポートです。",
      chooseEntry: "（入口サーバーを選択）",
      to: "から",
      sameServerWithIp: (ip) => `同じサーバー。出口 IP ${ip}（AirVPN の一覧）`,
      sameServer: "同じサーバー。出口 IP は接続後に「出口 IP を確認」で確認します",
      twoServers: "2 台のサーバー。出口 IP は出口サーバーのもので、接続後に「出口 IP を確認」で確認します",
      afterEntryChosen: "入口サーバーを選ぶと、接続はまずそこに届き、Mullvad の内部を通って出口へ転送されます",
    },
    servers: {
      label: "サーバー",
      search: (label) => `${label}を検索`,
      searchPlaceholder: "国、都市、サーバー名で検索",
      count: (count) => `${count} 台`,
      providerOwned: "自社所有",
      inactive: "停止中",
      cannotPick: "選択不可",
      noMatch: (query) => `「${query}」に一致するサーバーはありません`,
      matching: (count) => `${count} 台が一致。一覧はプロバイダーから直接取得しています。`,
      total: (count) => `全 ${count} 台。一覧はプロバイダーから直接取得しています。`,
    },
  },
});
