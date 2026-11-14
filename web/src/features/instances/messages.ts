// Text of the Connections page (連線): the list, the states of a connection and the reasons it needs attention, its
// actions and what sending them reports. The dialogs' text is in dialogs/messages.tsx and the inspector's in
// inspector/messages.tsx.

import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** "connection" or "connections", by the count. */
const connections = (count: number): string => (count === 1 ? "connection" : "connections");

export const m = defineMessages({
  en: {
    /** The state of a connection held closed by an emergency stop. */
    latched: "Emergency stopped",
    /** Why a connection needs attention (its list row, the overview). */
    attention: {
      latched: "Emergency stopped: every connection is refused until you release it",
      failed: "Cannot start: it retries by itself once the settings are fixed",
      degraded: "The tunnel probe failed; new connections are paused",
      retrying: (attempt: number, message: string) => `Automatic retry ${attempt} still did not succeed: ${message}`,
      intentNotDurable: "The latest intent is not written to disk yet",
      gatewayFailed: (port: number | null, error: string | null) =>
        `Gateway${port === null ? "" : ` :${port}`} cannot be enabled${error ? `: ${error}` : ""}`,
      dnsInterrupted:
        "DNS is interrupted: none of the DNS profile's servers answer, so names do not resolve until they recover",
      dnsFallback: "None of the DNS profile's servers answer; the WireGuard profile's DNS is used for now",
    },
    sort: { created: "Created" },
    /** The parts of a connection's configuration, as they are named inside a sentence. */
    part: {
      instance: "connection settings",
      profile: "WireGuard profile",
      dns: "DNS profile",
      security: "security profile",
    },
    staleConfig: (parts: readonly string[]) => `Changes to the ${listEn.format(parts)} apply only after a restart.`,
    action: {
      clearEmergency: "Release emergency stop",
      clearing: "Releasing",
      confirmStop: "Confirm stop",
      keepEmergency: "Keep emergency stop",
      emergencyStop: "Emergency stop",
      emergencyStopping: "Emergency stopping",
      checkExit: "Check exit IP",
      addGateway: "Add Gateway",
    },
    /** Why an action cannot run now. */
    reason: {
      sending: (action: string) => `“${action}” is being sent; wait until it is done`,
      checkNeedsReady: "The exit can be checked once the connection is ready",
      restartLatched: "Emergency stopped: release the emergency stop before restarting",
      restartNotRunning: "Only a running connection can be restarted",
      alreadyLatched: "Already emergency stopped",
      deleteUnknown: "The state is unknown, so it cannot be confirmed as stopped",
      deleteRunning: "A running connection cannot be deleted; stop it first",
    },
    /** What an accepted intent reports. */
    sent: {
      start: (name: string) => `Start requested for ${name}`,
      startDetail: "Connections open only after the tunnel is set up and verified.",
      restart: (name: string) => `Restart requested for ${name}`,
      restartMany: (count: number) => `Restart requested for ${count} ${connections(count)}`,
      restartDetail: "While it rebuilds, new connections are refused and never fall back to the ordinary network.",
      stop: (name: string) => `Stop requested for ${name}`,
      stopDetail: "The data path is not confirmed closed yet; the state updates once it is.",
      stopped: (name: string) => `${name} stopped`,
      stoppedNotDurable: "The data path is closed; the stop is not written to disk yet, and the system keeps retrying.",
      stoppedDetail: "The data path is closed.",
      emergencyCleared: (name: string) => `Emergency stop of ${name} released`,
      emergencyClearedDetail: "The connection stays stopped; start it when you need it.",
      emergency: (name: string) => `Emergency stop requested for ${name}`,
      emergencyDetail: "Not every connection is confirmed closed yet; the state updates once they are.",
      emergencyStopped: (name: string) => `${name} emergency stopped`,
      emergencyNotDurable:
        "The data path is closed; the emergency stop is not written to disk yet, and the system keeps retrying.",
      emergencyStoppedDetail: "Every connection is refused, and nothing resumes until you release it.",
      nothingToRestart: "No connection needs a restart",
      nothingToRestartDetail: "They have already restarted or stopped.",
    },
    /** After saving a WireGuard, DNS or security profile that connections use. */
    saved: {
      appliesOnNextStart: "Connections that use it apply it the next time they start.",
      restartNeeded: (count: number) =>
        count === 1
          ? "1 running connection still uses the earlier settings and takes the new ones only after a restart; restarting cuts the connections it carries now."
          : `${count} running connections still use the earlier settings and take the new ones only after a restart; restarting cuts the connections they carry now.`,
      restartOffer: (count: number) => `Restart the ${count} ${connections(count)} using it`,
    },
    /** What was attempted, for the report of a failure: the notification adds that it failed. */
    intent: {
      start: (name: string) => `Start ${name}`,
      stop: (name: string) => `Stop ${name}`,
      restart: (name: string) => `Restart ${name}`,
      clear_emergency: (name: string) => `Release the emergency stop of ${name}`,
      emergency_stop: (name: string) => `Emergency stop ${name}`,
    },
    list: {
      loading: "Loading connections",
      toolbar: "Connection list",
      search: "Search connections",
      searchPlaceholder: "Name, endpoint, city or port",
      /** After the count: "3 connections", "Showing 2/3 connections". */
      unit: (count: number) => connections(count),
      stale: (time: string) => `Cannot update: showing the data from ${time}`,
      liveRate: "Live rate",
      trafficUnknown: "Traffic state unknown",
      /** A Gateway's chip in a row: its name and its state. */
      gatewayState: (name: string, state: string) => `${name}: ${state}`,
      noMatch: "No connection matches",
      emptyTitle: "No connections yet",
      emptyBody:
        "Each connection is an independent WireGuard exit: once created, it is used through a local Gateway (SOCKS5 or HTTP), and its traffic only ever goes through this tunnel.",
      add: "Add connection",
    },
    filter: {
      attention: "Needs attention",
      allTitle: "Every connection",
      runningTitle: "Connections set to run",
      stoppedTitle: "Connections set to stop",
      attentionTitle: "A problem, or settings that apply only after a restart",
    },
    /** The list's batch action: restart the running connections whose saved settings wait for a restart. */
    restartPending: {
      none: "No running connection has settings waiting to apply",
      label: "Restart the connections with pending settings",
      labelCount: (count: number) => `Restart the ${count} ${connections(count)} with pending settings`,
      text: "Restart pending",
      confirmTitle: (count: number) => `Restart ${count} ${connections(count)}?`,
      confirm: (count: number) => `Restart ${count} ${connections(count)}`,
      changed: (names: readonly string[]) =>
        `The settings of ${listEn.format(names.map((name) => `“${name}”`))} changed and apply only after a restart.`,
      effect:
        "While they restart, the connections they carry now are cut and new ones are refused, never falling back to the ordinary network; other connections are not affected.",
    },
    page: {
      description: "Each connection is an independent WireGuard exit.",
      help: "Traffic a Gateway receives leaves only through its tunnel; while the tunnel is unavailable it is always refused and never falls back to the ordinary network. Select a connection to see its handshake, DNS and exit evidence, and to start it, stop it or act on it otherwise.",
      helpText:
        "Traffic a Gateway receives leaves only through its tunnel; while the tunnel is unavailable it is always refused and never falls back to the ordinary network.",
      detailsOf: (name: string) => `Details of ${name}`,
      details: "Connection details",
      notFound: "Connection not found",
      select: "Select a connection",
      selectHint: "See its live traffic, handshake and DNS evidence, Gateways and actions.",
    },
  },
  "zh-TW": {
    latched: "已急停",
    attention: {
      latched: "已急停，解除前所有連線都被拒絕",
      failed: "無法啟動：修正相關設定後會自動再試",
      degraded: "tunnel 探測失敗，暫停接受新連線",
      retrying: (attempt, message) => `自動重試第 ${attempt} 次仍未成功：${message}`,
      intentNotDurable: "最新的操作意圖尚未寫入磁碟",
      gatewayFailed: (port, error) => `代理埠 ${port === null ? "" : `:${port}`} 無法啟用${error ? `：${error}` : ""}`,
      dnsInterrupted: "DNS 已中斷：DNS 設定的伺服器都沒有回應，名稱無法解析，直到它們恢復",
      dnsFallback: "DNS 設定的伺服器都沒有回應，暫時改用 WireGuard 設定的 DNS",
    },
    sort: { created: "建立時間" },
    part: { instance: "連線設定", profile: "WireGuard 設定", dns: "DNS 設定", security: "安全設定" },
    staleConfig: (parts) => `${parts.join("、")}已變更，重新啟動後才會套用。`,
    action: {
      clearEmergency: "解除急停",
      clearing: "解除中",
      confirmStop: "確認停止",
      keepEmergency: "維持急停",
      emergencyStop: "急停",
      emergencyStopping: "急停中",
      checkExit: "檢查出口 IP",
      addGateway: "新增代理埠",
    },
    reason: {
      sending: (action) => `正在送出「${action}」，完成後再操作`,
      checkNeedsReady: "連線就緒後才能檢查",
      restartLatched: "已急停：解除急停後才能重新啟動",
      restartNotRunning: "只有執行中的連線可以重新啟動",
      alreadyLatched: "已在急停狀態",
      deleteUnknown: "狀態未知，無法確認已停止",
      deleteRunning: "執行中的連線不能刪除，請先停止",
    },
    sent: {
      start: (name) => `已送出啟動 ${name}`,
      startDetail: "建立並驗證 tunnel 後才會開放連線。",
      restart: (name) => `已送出重新啟動 ${name}`,
      restartMany: (count) => `已送出重新啟動 ${count} 條連線`,
      restartDetail: "重建期間新連線會被拒絕，不會改走一般網路。",
      stop: (name) => `已送出停止 ${name}`,
      stopDetail: "尚未確認資料路徑已封閉；狀態會在確認後更新。",
      stopped: (name) => `已停止 ${name}`,
      stoppedNotDurable: "資料路徑已封閉；停止狀態尚未寫入磁碟，系統會持續重試。",
      stoppedDetail: "資料路徑已封閉。",
      emergencyCleared: (name) => `已解除 ${name} 的急停`,
      emergencyClearedDetail: "連線維持停止，需要時再啟動。",
      emergency: (name) => `已送出急停 ${name}`,
      emergencyDetail: "尚未確認所有連線都已封閉；狀態會在確認後更新。",
      emergencyStopped: (name) => `${name} 已急停`,
      emergencyNotDurable: "資料路徑已封閉；急停狀態尚未寫入磁碟，系統會持續重試。",
      emergencyStoppedDetail: "所有連線都被拒絕，解除前不會自動恢復。",
      nothingToRestart: "沒有需要重新啟動的連線",
      nothingToRestartDetail: "它們已經重新啟動或停止。",
    },
    saved: {
      appliesOnNextStart: "使用它的連線會在下次啟動時套用。",
      restartNeeded: (count) =>
        `${count} 條執行中的連線仍使用先前的設定，重新啟動後才會套用；重新啟動會中斷它們目前的連線。`,
      restartOffer: (count) => `重新啟動使用中的 ${count} 條連線`,
    },
    intent: {
      start: (name) => `啟動 ${name}`,
      stop: (name) => `停止 ${name}`,
      restart: (name) => `重新啟動 ${name}`,
      clear_emergency: (name) => `解除急停 ${name}`,
      emergency_stop: (name) => `急停 ${name}`,
    },
    list: {
      loading: "載入連線",
      toolbar: "連線清單",
      search: "搜尋連線",
      searchPlaceholder: "名稱、端點、城市或埠號",
      unit: () => "條連線",
      stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
      liveRate: "即時速率",
      trafficUnknown: "流量狀態未知",
      gatewayState: (name, state) => `${name}：${state}`,
      noMatch: "沒有符合條件的連線",
      emptyTitle: "還沒有任何連線",
      emptyBody:
        "每條連線是一個獨立的 WireGuard 出口：建立後透過本機代理埠（SOCKS5／HTTP）使用，流量只會經過這條 tunnel。",
      add: "新增連線",
    },
    filter: {
      attention: "需要處理",
      allTitle: "所有連線",
      runningTitle: "設定為執行的連線",
      stoppedTitle: "設定為停止的連線",
      attentionTitle: "有問題，或設定要重新啟動才會套用",
    },
    restartPending: {
      none: "沒有設定待套用的執行中連線",
      label: "重新啟動待套用的連線",
      labelCount: (count) => `重新啟動待套用的 ${count} 條連線`,
      text: "重新啟動待套用",
      confirmTitle: (count) => `重新啟動 ${count} 條連線？`,
      confirm: (count) => `重新啟動 ${count} 條連線`,
      changed: (names) => `${names.map((name) => `「${name}」`).join("、")}的設定已變更，重新啟動後才會套用。`,
      effect: "重新啟動期間它們目前的連線會中斷、新連線會被拒絕，不會改走一般網路；其他連線不受影響。",
    },
    page: {
      description: "每條連線是一個獨立的 WireGuard 出口。",
      help: "代理埠收到的流量只經它的 tunnel 送出；tunnel 不可用時一律拒絕，不會改走一般網路。選一條連線查看它的握手、DNS 與出口證據，以及啟動、停止與其他操作。",
      helpText: "代理埠收到的流量只經它的 tunnel 送出；tunnel 不可用時一律拒絕，不會改走一般網路。",
      detailsOf: (name) => `${name} 的詳細資料`,
      details: "連線詳細資料",
      notFound: "找不到這條連線",
      select: "選擇一條連線",
      selectHint: "查看即時流量、握手與 DNS 證據、代理埠與操作。",
    },
  },
  ja: {
    latched: "緊急停止中",
    attention: {
      latched: "緊急停止中：解除するまですべての接続が拒否されます",
      failed: "開始できません：関連する設定を修正すると自動的に再試行します",
      degraded: "トンネルの疎通確認に失敗：新しい接続の受け付けを一時停止しています",
      retrying: (attempt, message) => `自動再試行 ${attempt} 回目も成功していません：${message}`,
      intentNotDurable: "最新の目標の状態はまだディスクに書き込まれていません",
      gatewayFailed: (port, error) =>
        `ゲートウェイ${port === null ? "" : ` :${port} `}を有効にできません${error ? `：${error}` : ""}`,
      dnsInterrupted: "DNS が中断しています：DNS 設定のサーバーがどれも応答せず、復旧するまで名前解決ができません",
      dnsFallback: "DNS 設定のサーバーがどれも応答しないため、一時的に WireGuard 設定の DNS を使用しています",
    },
    sort: { created: "作成日時" },
    part: { instance: "接続設定", profile: "WireGuard 設定", dns: "DNS 設定", security: "セキュリティ設定" },
    staleConfig: (parts) => `${parts.join("、")}が変更されました。再起動すると適用されます。`,
    action: {
      clearEmergency: "緊急停止を解除",
      clearing: "解除中",
      confirmStop: "停止を確定",
      keepEmergency: "緊急停止を維持",
      emergencyStop: "緊急停止",
      emergencyStopping: "緊急停止を実行中",
      checkExit: "出口 IP を確認",
      addGateway: "ゲートウェイを追加",
    },
    reason: {
      sending: (action) => `「${action}」を送信中です。完了してから操作してください`,
      checkNeedsReady: "接続の準備が完了してから確認できます",
      restartLatched: "緊急停止中：緊急停止を解除してから再起動してください",
      restartNotRunning: "再起動できるのは実行中の接続だけです",
      alreadyLatched: "すでに緊急停止中です",
      deleteUnknown: "状態が不明なため、停止済みかどうか確認できません",
      deleteRunning: "実行中の接続は削除できません。先に停止してください",
    },
    sent: {
      start: (name) => `${name} の開始を要求しました`,
      startDetail: "トンネルを確立して検証した後に、接続を受け付けます。",
      restart: (name) => `${name} の再起動を要求しました`,
      restartMany: (count) => `${count} 件の接続の再起動を要求しました`,
      restartDetail: "再構築中、新しい接続は拒否され、通常のネットワークには切り替わりません。",
      stop: (name) => `${name} の停止を要求しました`,
      stopDetail: "データ経路が閉じたことはまだ確認できていません。確認でき次第、状態が更新されます。",
      stopped: (name) => `${name} を停止しました`,
      stoppedNotDurable:
        "データ経路は閉じました。停止状態はまだディスクに書き込まれておらず、システムが再試行を続けます。",
      stoppedDetail: "データ経路は閉じました。",
      emergencyCleared: (name) => `${name} の緊急停止を解除しました`,
      emergencyClearedDetail: "接続は停止したままです。必要なときに開始してください。",
      emergency: (name) => `${name} の緊急停止を要求しました`,
      emergencyDetail: "すべての接続が閉じたことはまだ確認できていません。確認でき次第、状態が更新されます。",
      emergencyStopped: (name) => `${name} を緊急停止しました`,
      emergencyNotDurable:
        "データ経路は閉じました。緊急停止状態はまだディスクに書き込まれておらず、システムが再試行を続けます。",
      emergencyStoppedDetail: "すべての接続が拒否され、解除するまで自動では再開しません。",
      nothingToRestart: "再起動が必要な接続はありません",
      nothingToRestartDetail: "すでに再起動または停止しています。",
    },
    saved: {
      appliesOnNextStart: "これを使う接続には、次回の開始時に適用されます。",
      restartNeeded: (count) =>
        `実行中の ${count} 件の接続は以前の設定のままで、再起動すると新しい設定が適用されます。再起動すると、現在の通信は切断されます。`,
      restartOffer: (count) => `使用中の ${count} 件の接続を再起動`,
    },
    intent: {
      start: (name) => `${name} の開始`,
      stop: (name) => `${name} の停止`,
      restart: (name) => `${name} の再起動`,
      clear_emergency: (name) => `${name} の緊急停止の解除`,
      emergency_stop: (name) => `${name} の緊急停止`,
    },
    list: {
      loading: "接続を読み込み中",
      toolbar: "接続一覧",
      search: "接続を検索",
      searchPlaceholder: "名前、都市、ポートなど",
      unit: () => "件の接続",
      stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
      liveRate: "リアルタイム速度",
      trafficUnknown: "トラフィックの状態は不明",
      gatewayState: (name, state) => `${name}：${state}`,
      noMatch: "条件に一致する接続はありません",
      emptyTitle: "接続はまだありません",
      emptyBody:
        "接続はそれぞれ独立した WireGuard 出口です。作成後はローカルのゲートウェイ（SOCKS5／HTTP）経由で利用し、トラフィックはこのトンネルだけを通ります。",
      add: "接続を追加",
    },
    filter: {
      attention: "要対応",
      allTitle: "すべての接続",
      runningTitle: "実行に設定されている接続",
      stoppedTitle: "停止に設定されている接続",
      attentionTitle: "問題がある、または再起動しないと設定が適用されない",
    },
    restartPending: {
      none: "設定が適用待ちの実行中の接続はありません",
      label: "適用待ちの接続を再起動",
      labelCount: (count) => `適用待ちの ${count} 件の接続を再起動`,
      text: "適用待ちを再起動",
      confirmTitle: (count) => `${count} 件の接続を再起動しますか？`,
      confirm: (count) => `${count} 件の接続を再起動`,
      changed: (names) =>
        `${names.map((name) => `「${name}」`).join("、")}の設定が変更されました。再起動すると適用されます。`,
      effect:
        "再起動中は、現在の通信が切断され、新しい接続は拒否されます。通常のネットワークには切り替わりません。他の接続には影響しません。",
    },
    page: {
      description: "接続はそれぞれ独立した WireGuard 出口です。",
      help: "ゲートウェイが受け取ったトラフィックは、そのトンネルだけを通って送信されます。トンネルが使えない間はすべて拒否され、通常のネットワークには切り替わりません。接続を選ぶと、ハンドシェイク、DNS、出口のエビデンスの確認と、開始・停止などの操作ができます。",
      helpText:
        "ゲートウェイが受け取ったトラフィックは、そのトンネルだけを通って送信されます。トンネルが使えない間はすべて拒否され、通常のネットワークには切り替わりません。",
      detailsOf: (name) => `${name} の詳細`,
      details: "接続の詳細",
      notFound: "この接続が見つかりません",
      select: "接続を選択",
      selectHint: "リアルタイムトラフィック、ハンドシェイクと DNS のエビデンス、ゲートウェイ、操作を確認できます。",
    },
  },
});
