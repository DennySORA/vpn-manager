// Text of the Provider egress (where every provider request leaves): the strip at the top of the Providers page, its
// actions and its two dialogs, and the function checks (each provider's gates and the last exit check). 直連 is the
// direct connection: provider requests leave through this computer's ordinary network, for 10 minutes at most — once
// for the first setup (首次直連), or again to recover the egress (重新直連, "direct reconnection").

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

/** The space between a name that ends in a Latin letter or a digit and the Japanese after it: 「AirVPN の」. */
function gapJa(name: string): string {
  return /[A-Za-z0-9)]$/.test(name) ? " " : "";
}

export const m = defineMessages({
  en: {
    /** The egress by name: the strip's accessible name and the title of the dialog that chooses it. */
    title: "Provider egress",
    /** The strip's title in each phase of the egress. */
    phase: {
      unconfigured: "No Provider egress yet",
      bootstrap_direct: "First direct connection open",
      starting_instance: "Egress connection starting",
      switching: "Waiting for the new connection to become the egress",
      vpn_ready: "Through the VPN egress",
      blocked: "Egress connection unusable",
      recovery_required: "The egress needs recovery",
      disabled: "Provider egress disabled",
      /** A manual rebootstrap's grant is open. */
      rebootstrap: "Direct reconnection open (recovering the egress)",
    },
    /** What the strip says under its title, by phase (the service's own reason is shown instead where it gives one). */
    body: {
      vpnReady:
        "Every provider request, such as signing in, devices and server lists, leaves through this VPN, never through this computer's ordinary network.",
      starting: "Provider operations wait until the egress connection is up.",
      switching: "The new connection becomes the egress by itself once it is up.",
      rebootstrap:
        "Provider requests leave through this computer's ordinary network for now, not through a VPN, and only to recover the egress: the account, devices and keys, the server list, and creating one new connection. Once the new connection is up it becomes the egress by itself and the direct connection closes.",
      firstSetup:
        "Add an account and create the first connection; once it is up it becomes the egress by itself, the direct connection ends, and it is never opened again.",
      /** `text` and the service's reason for the last attempt. */
      lastTime: (text: string, reason: string) => `${text} Last time: ${reason}`,
      recovery: "The egress connection cannot recover by itself.",
      chooseEgress: "Choose a VPN connection as the egress; provider requests never fall back to the ordinary network.",
      importFirst:
        "The first direct connection has been used and is not opened again: import a WireGuard profile and create a connection first, then choose it as the egress.",
      chooseOrDirect:
        "Choose a VPN connection that reaches the Internet as the egress. For the first setup only, you can also connect directly once (10 minutes at most).",
      directOnce:
        "For the first setup you can connect directly once (10 minutes at most, only to the provider's fixed addresses) to sign in to the account and create the first VPN connection; after that, only through the VPN.",
      /** `text` and the service's reason for the last setting. */
      lastSetting: (text: string, reason: string) => `${text} Last setting: ${reason}`,
      blocked:
        "The egress connection is not running; provider operations pause until it recovers (it is never switched automatically).",
      disabled: "No provider request is sent.",
      disabledNoConnections:
        "No provider request is sent. Once it is enabled, you can choose an egress connection or create the first connection.",
    },
    /** After the title: the egress connection's name. */
    instanceName: (name: string) => `: ${name}`,
    nameUnknown: "(name unknown)",
    /** How long a direct grant stays open; `time` is the countdown (mm:ss). */
    left: {
      direct: (time: ReactNode): ReactNode => <>{time} left</>,
      rebootstrap: (time: ReactNode): ReactNode => <>Direct reconnection: {time} left</>,
      firstSetup: (time: ReactNode): ReactNode => <>First direct connection: {time} left</>,
    },
    lastCheck: "Latest check",
    /** The strip's line of `owner`'s function checks. */
    checksIn: (owner: string) => `Function checks (${owner})`,
    /** The selected egress cannot come back by itself, and the service does not allow a direct reconnection. */
    noRebootstrap: "Cannot reconnect directly",
    firstSetupOpened: "The first direct connection is open",
    firstSetupOpenedDetail: "Valid for 10 minutes, only to the provider's fixed addresses.",
    rebootstrapCancelled: "The direct reconnection was cancelled",
    rebootstrapCancelledDetail: "The direct connection is closed; provider operations go through the VPN only.",
    /** What a failed operation is reported as (the notification adds that it failed). */
    failed: {
      check: "Check exit",
      openFirstSetup: "Open the first direct connection",
      endDirect: "End the direct connection",
      cancelRebootstrap: "Cancel the direct reconnection",
      enable: "Enable the Provider egress",
    },
    actions: {
      choose: "Choose egress connection…",
      noConnection: "There is no connection to choose yet: create a connection first",
      openInstance: "Go to the egress connection",
      opening: "Opening",
      importProfile: "Import WireGuard profile",
      cancelRebootstrap: "Cancel the direct reconnection",
      cancelling: "Cancelling",
      endDirect: "End the direct connection",
      ending: "Ending",
      rebootstrap: "Rebuild the egress over the ordinary network…",
      enable: "Enable the Provider egress",
      check: "Check exit",
      checkUnavailable:
        "The exit can be checked only while it is usable (through the VPN egress, or during the direct connection)",
    },
    /** The manual rebootstrap: what leaves without a VPN, for how long and for what, acknowledged first. */
    rebootstrap: {
      title: "Rebuild the egress over this computer's network",
      description: "A one-time exception for when the egress connection cannot recover by itself, 10 minutes at most.",
      tickFirst: "First tick “I understand” above",
      open: "Open the direct reconnection (10 minutes)",
      exposure: "Provider requests skip the VPN during this time",
      exposureDetail:
        "Signing in, reading the devices and keys and the server list, and creating one new egress connection go straight to the provider's fixed addresses over this computer's current network: the provider and your network operator can see this computer's IP address.",
      terms: {
        time: "Open for 10 minutes only; you can cancel it at any time, and it closes by itself when it expires or the service restarts.",
        scope:
          "Only for recovering the egress: other provider operations (revoking a device or downloading an IP blocklist, for example) never use the direct connection.",
        takeover:
          "Create a new connection during this time; once it is up and the exit is confirmed through it, it becomes the Provider egress by itself and the direct connection closes.",
        once: "This does not give back the first direct connection; every provider request afterwards still goes through the VPN only.",
      },
      understood:
        "I understand: for these 10 minutes, the provider requests that recover the egress leave through this computer's ordinary network, not through a VPN.",
      opened: "The direct reconnection is open",
      openedDetail:
        "Create a new egress connection within 10 minutes; the direct connection closes as soon as it is up.",
    },
    /** The dialog that chooses the egress connection. */
    choose: {
      description:
        "Provider requests leave only through the connection chosen here. While the egress is down, operations pause and wait for it to recover; it is never switched automatically.",
      label: "Egress connection",
      apply: "Apply",
      applying: "Applying",
      chooseFirst: "Choose a connection first",
      isCurrent: "This is the current setting",
      disable: "Disable the Provider egress",
      disableHint: "Sends no provider requests",
      disabled: "The Provider egress was disabled",
      changed: "The Provider egress was changed",
    },
    /** One exit check: where the address was seen and what that proves. */
    check: {
      failed: "Check failed",
      providerExit: (provider: string) => `${provider} exit`,
      notProviderExit: (provider: string) => `Not an exit of ${provider}`,
      unknownProvider: "Cannot tell which provider the exit belongs to",
      placeUnknown: "Location unknown",
      notCompleted: "Could not complete the check",
      exitServer: (server: string) => `Exit ${server}`,
      direct: "Direct, not through the VPN",
      viaTunnel: "Through the tunnel",
    },
    /** Each provider's function gates. */
    gate: {
      /** An exit check of an imported configuration file: `checker` observes the address, proving no provider. */
      exitObservation: (checker: string) => `Exit observation (${checker})`,
      exitCheck: (checker: string) => `Exit check (${checker})`,
      membership: "Exit ownership",
      ipv6: "IPv6 exit",
      configGenerator: "Generating connection settings",
      forward: "Forwarded port reservation",
      /** A gate and its state on one tag. */
      state: (gate: string, state: string) => `${gate}: ${state}`,
      status: {
        passed: "Passed",
        failed: "Failed",
        blocked: "Cannot do it for you",
        not_applicable: "Not applicable",
        unverified: "Not confirmed yet",
      },
      notObserved: "Not observed yet",
      /** The list of `owner`'s function checks. */
      checksOf: (owner: string) => `Function checks: ${owner}`,
      /** Whose functions the gates of a generic provider are about. */
      genericOwner: "generic configuration files",
    },
  },
  "zh-TW": {
    title: "Provider 出口",
    phase: {
      unconfigured: "還沒有 Provider 出口",
      bootstrap_direct: "首次直連中",
      starting_instance: "出口連線啟動中",
      switching: "等待新連線成為出口",
      vpn_ready: "經 VPN 出口",
      blocked: "出口連線無法使用",
      recovery_required: "出口需要恢復",
      disabled: "Provider 出口已停用",
      rebootstrap: "重新直連中（恢復出口）",
    },
    body: {
      vpnReady: "登入、裝置與伺服器清單等所有供應商請求都經這條 VPN 送出，不經這台電腦的一般網路。",
      starting: "出口連線完成連線前，供應商操作會等待。",
      switching: "新連線完成連線後會自動成為出口。",
      rebootstrap:
        "供應商請求暫時經這台電腦的一般網路送出，不經 VPN，而且只限恢復出口：帳號、裝置與金鑰、伺服器清單、建立一條新連線。新連線連上後會自動成為出口，直連隨即關閉。",
      firstSetup: "加入帳號並建立第一條連線；它連上後會自動成為出口，直連隨即結束，之後不會再開放。",
      lastTime: (text, reason) => `${text} 上一次：${reason}`,
      recovery: "出口連線無法自行恢復。",
      chooseEgress: "請選擇一條 VPN 連線作為出口；供應商請求不會改走一般網路。",
      importFirst: "首次直連已經用過，不會再開放：請先匯入一份 WireGuard 設定並建立連線，再把它選為出口。",
      chooseOrDirect:
        "請選擇一條能連上網際網路的 VPN 連線作為出口。也可以只在第一次設定時直接連線一次（最多 10 分鐘）。",
      directOnce:
        "第一次設定時，可以直接連線一次（最多 10 分鐘，只能連到供應商的固定網址）來登入帳號並建立第一條 VPN 連線；之後只經 VPN。",
      lastSetting: (text, reason) => `${text} 上次設定：${reason}`,
      blocked: "出口連線沒有在執行；供應商操作會暫停，直到它恢復（不會自動換線）。",
      disabled: "不會送出任何供應商請求。",
      disabledNoConnections: "不會送出任何供應商請求。啟用後可以選擇出口連線，或建立第一條連線。",
    },
    instanceName: (name) => `：${name}`,
    nameUnknown: "（名稱未知）",
    left: {
      direct: (time) => <>剩 {time}</>,
      rebootstrap: (time) => <>重新直連剩 {time}</>,
      firstSetup: (time) => <>首次直連剩 {time}</>,
    },
    lastCheck: "最近檢查",
    checksIn: (owner) => `功能檢查（${owner}）`,
    noRebootstrap: "不能重新直連",
    firstSetupOpened: "已開啟首次直連",
    firstSetupOpenedDetail: "10 分鐘內有效，只能連到供應商的固定網址。",
    rebootstrapCancelled: "已取消重新直連",
    rebootstrapCancelledDetail: "直連已關閉；供應商操作只經 VPN。",
    failed: {
      check: "檢查出口",
      openFirstSetup: "開啟首次直連",
      endDirect: "結束直連",
      cancelRebootstrap: "取消重新直連",
      enable: "啟用 Provider 出口",
    },
    actions: {
      choose: "選擇出口連線…",
      noConnection: "還沒有連線可以選：先建立一條連線",
      openInstance: "前往出口連線",
      opening: "開啟中",
      importProfile: "匯入 WireGuard 設定",
      cancelRebootstrap: "取消重新直連",
      cancelling: "取消中",
      endDirect: "結束直連",
      ending: "結束中",
      rebootstrap: "以一般網路重新建立出口…",
      enable: "啟用 Provider 出口",
      check: "檢查出口",
      checkUnavailable: "出口可用時才能檢查（經 VPN 出口或直連期間）",
    },
    rebootstrap: {
      title: "以這台電腦的網路重新建立出口",
      description: "出口連線無法自行恢復時的一次性例外，最多 10 分鐘。",
      tickFirst: "先勾選上方的「我了解」",
      open: "開啟重新直連（10 分鐘）",
      exposure: "這段時間的供應商請求不經 VPN",
      exposureDetail:
        "登入帳號、讀取裝置與金鑰、伺服器清單、建立一條新的出口連線，會經這台電腦目前的網路直接送到供應商的固定網址：供應商與你的網路業者看得到這台電腦的 IP 位址。",
      terms: {
        time: "只開放 10 分鐘；可以隨時取消，到期或服務重新啟動時自動關閉。",
        scope: "只用於恢復出口：其他供應商操作（例如撤銷裝置、下載 IP 封鎖清單）不會使用直連。",
        takeover: "在這段時間建立一條新連線；它連上、並經它確認出口後，會自動成為 Provider 出口，直連隨即關閉。",
        once: "首次直連的機會不會因此恢復；之後所有供應商請求仍只經 VPN。",
      },
      understood: "我了解：這 10 分鐘內，恢復出口的供應商請求會經這台電腦的一般網路送出，不經 VPN。",
      opened: "已開啟重新直連",
      openedDetail: "10 分鐘內建立一條新的出口連線；它連上後直連隨即關閉。",
    },
    choose: {
      description: "供應商請求只經這裡選的連線送出。出口斷線時操作會暫停並等它恢復，不會自動換線。",
      label: "出口連線",
      apply: "套用",
      applying: "套用中",
      chooseFirst: "先選擇一條連線",
      isCurrent: "這就是目前的設定",
      disable: "停用 Provider 出口",
      disableHint: "不送出任何供應商請求",
      disabled: "已停用 Provider 出口",
      changed: "已變更 Provider 出口",
    },
    check: {
      failed: "檢查失敗",
      providerExit: (provider) => `${provider} 出口`,
      notProviderExit: (provider) => `不是 ${provider} 出口`,
      unknownProvider: "無法判定出口屬於哪家供應商",
      placeUnknown: "地點未知",
      notCompleted: "無法完成檢查",
      exitServer: (server) => `出口 ${server}`,
      direct: "直連，未經 VPN",
      viaTunnel: "經 tunnel",
    },
    gate: {
      exitObservation: (checker) => `出口觀測（${checker}）`,
      exitCheck: (checker) => `出口檢查（${checker}）`,
      membership: "出口歸屬",
      ipv6: "IPv6 出口",
      configGenerator: "產生連線設定",
      forward: "轉發 port 保留",
      state: (gate, state) => `${gate}：${state}`,
      status: {
        passed: "通過",
        failed: "未通過",
        blocked: "無法代辦",
        not_applicable: "不適用",
        unverified: "尚未確認",
      },
      notObserved: "尚未觀測",
      checksOf: (owner) => `${owner} 功能檢查`,
      genericOwner: "一般設定檔",
    },
  },
  ja: {
    title: "Provider 出口",
    phase: {
      unconfigured: "Provider 出口はまだありません",
      bootstrap_direct: "初回の直接接続中",
      starting_instance: "出口接続を起動中",
      switching: "新しい接続が出口になるのを待機中",
      vpn_ready: "VPN 出口経由",
      blocked: "出口接続を使用できません",
      recovery_required: "出口の復旧が必要です",
      disabled: "Provider 出口は無効です",
      rebootstrap: "再度の直接接続中（出口の復旧）",
    },
    body: {
      vpnReady:
        "ログイン、デバイス、サーバー一覧など、プロバイダーへのリクエストはすべてこの VPN を通って送信され、このコンピューターの通常のネットワークは通りません。",
      starting: "出口接続が確立するまで、プロバイダーの操作は待機します。",
      switching: "新しい接続は、確立すると自動的に出口になります。",
      rebootstrap:
        "プロバイダーへのリクエストは一時的にこのコンピューターの通常のネットワークを通って送信され、VPN は通りません。用途は出口の復旧（アカウント、デバイスと鍵、サーバー一覧、新しい接続 1 つの作成）に限られます。新しい接続が確立すると自動的に出口になり、直接接続はすぐに閉じます。",
      firstSetup:
        "アカウントを追加して最初の接続を作成してください。その接続が確立すると自動的に出口になり、直接接続はすぐに終了して、以後は開放されません。",
      lastTime: (text, reason) => `${text}前回：${reason}`,
      recovery: "出口接続は自力で復旧できません。",
      chooseEgress:
        "VPN 接続を 1 つ出口として選んでください。プロバイダーへのリクエストが通常のネットワークに切り替わることはありません。",
      importFirst:
        "初回の直接接続は使用済みで、再び開放されることはありません。先に WireGuard 設定をインポートして接続を作成し、それを出口として選んでください。",
      chooseOrDirect:
        "インターネットに接続できる VPN 接続を出口として選んでください。初回の設定時に限り、一度だけ直接接続することもできます（最大 10 分）。",
      directOnce:
        "初回の設定時は、一度だけ直接接続して（最大 10 分、プロバイダーの固定アドレスのみ）アカウントにログインし、最初の VPN 接続を作成できます。以後は VPN 経由のみです。",
      lastSetting: (text, reason) => `${text}前回の設定：${reason}`,
      blocked:
        "出口接続が実行されていません。復旧するまでプロバイダーの操作は一時停止します（自動では切り替わりません）。",
      disabled: "プロバイダーへのリクエストは一切送信されません。",
      disabledNoConnections:
        "プロバイダーへのリクエストは一切送信されません。有効にすると、出口接続を選ぶか、最初の接続を作成できます。",
    },
    instanceName: (name) => `：${name}`,
    nameUnknown: "（名前不明）",
    left: {
      direct: (time) => <>残り {time}</>,
      rebootstrap: (time) => <>再度の直接接続：残り {time}</>,
      firstSetup: (time) => <>初回の直接接続：残り {time}</>,
    },
    lastCheck: "最新のチェック",
    checksIn: (owner) => `機能チェック（${owner}）`,
    noRebootstrap: "再度の直接接続はできません",
    firstSetupOpened: "初回の直接接続を開始しました",
    firstSetupOpenedDetail: "有効期間は 10 分で、接続先はプロバイダーの固定アドレスだけです。",
    rebootstrapCancelled: "再度の直接接続をキャンセルしました",
    rebootstrapCancelledDetail: "直接接続は閉じました。プロバイダーの操作は VPN だけを通ります。",
    failed: {
      check: "出口の確認",
      openFirstSetup: "初回の直接接続の開始",
      endDirect: "直接接続の終了",
      cancelRebootstrap: "再度の直接接続のキャンセル",
      enable: "Provider 出口の有効化",
    },
    actions: {
      choose: "出口接続を選択…",
      noConnection: "選べる接続がまだありません：先に接続を作成してください",
      openInstance: "出口接続へ移動",
      opening: "開始中",
      importProfile: "WireGuard 設定をインポート",
      cancelRebootstrap: "再度の直接接続をキャンセル",
      cancelling: "キャンセル中",
      endDirect: "直接接続を終了",
      ending: "終了中",
      rebootstrap: "通常のネットワークで出口を作り直す…",
      enable: "Provider 出口を有効化",
      check: "出口を確認",
      checkUnavailable: "出口を確認できるのは、出口が使えるとき（VPN 出口経由、または直接接続中）だけです",
    },
    rebootstrap: {
      title: "このコンピューターのネットワークで出口を作り直す",
      description: "出口接続が自力で復旧できない場合の一度限りの例外で、最大 10 分です。",
      tickFirst: "先に上の「理解しました」にチェックを入れてください",
      open: "再度の直接接続を開始（10 分）",
      exposure: "この間のプロバイダーへのリクエストは VPN を通りません",
      exposureDetail:
        "アカウントへのログイン、デバイスと鍵、サーバー一覧の読み込み、新しい出口接続 1 つの作成は、このコンピューターの現在のネットワークを通ってプロバイダーの固定アドレスに直接送信されます。プロバイダーとあなたのネットワーク事業者には、このコンピューターの IP アドレスが見えます。",
      terms: {
        time: "開放されるのは 10 分間だけです。いつでもキャンセルでき、期限切れまたはサービスの再起動で自動的に閉じます。",
        scope:
          "出口の復旧にだけ使われます。ほかのプロバイダー操作（デバイスの失効や IP ブロックリストのダウンロードなど）は直接接続を使いません。",
        takeover:
          "この間に新しい接続を 1 つ作成してください。その接続が確立し、その接続経由で出口が確認されると自動的に Provider 出口になり、直接接続はすぐに閉じます。",
        once: "これによって初回の直接接続の機会が戻ることはありません。以後もプロバイダーへのリクエストはすべて VPN だけを通ります。",
      },
      understood:
        "理解しました：この 10 分間、出口を復旧するためのプロバイダーへのリクエストは、VPN を通らずにこのコンピューターの通常のネットワークを通って送信されます。",
      opened: "再度の直接接続を開始しました",
      openedDetail: "10 分以内に新しい出口接続を作成してください。その接続が確立すると直接接続はすぐに閉じます。",
    },
    choose: {
      description:
        "プロバイダーへのリクエストは、ここで選んだ接続だけを通って送信されます。出口が切断されると操作は一時停止して復旧を待ち、自動では切り替わりません。",
      label: "出口接続",
      apply: "適用",
      applying: "適用中",
      chooseFirst: "先に接続を選んでください",
      isCurrent: "これが現在の設定です",
      disable: "Provider 出口を無効化",
      disableHint: "プロバイダーへのリクエストを送信しない",
      disabled: "Provider 出口を無効にしました",
      changed: "Provider 出口を変更しました",
    },
    check: {
      failed: "チェック失敗",
      providerExit: (provider) => `${provider}${gapJa(provider)}の出口`,
      notProviderExit: (provider) => `${provider}${gapJa(provider)}の出口ではありません`,
      unknownProvider: "出口がどのプロバイダーのものか判定できません",
      placeUnknown: "場所不明",
      notCompleted: "チェックを完了できませんでした",
      exitServer: (server) => `出口 ${server}`,
      direct: "直接接続、VPN 経由なし",
      viaTunnel: "トンネル経由",
    },
    gate: {
      exitObservation: (checker) => `出口の観測（${checker}）`,
      exitCheck: (checker) => `出口チェック（${checker}）`,
      membership: "出口の帰属",
      ipv6: "IPv6 出口",
      configGenerator: "接続設定の生成",
      forward: "転送ポートの予約",
      state: (gate, state) => `${gate}：${state}`,
      status: {
        passed: "合格",
        failed: "不合格",
        blocked: "代行できません",
        not_applicable: "対象外",
        unverified: "未確認",
      },
      notObserved: "未観測",
      checksOf: (owner) => `${owner}${gapJa(owner)}の機能チェック`,
      genericOwner: "汎用設定ファイル",
    },
  },
});
