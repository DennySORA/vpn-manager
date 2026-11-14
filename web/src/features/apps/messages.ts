// Text of the Managed apps page (/apps): the words its parts share, the model's state names, reasons and validation
// messages, the actions with their notifications and confirmations, the list page, and the resource list the system
// pages show. For size, three sub-areas keep tables of their own: access/messages.tsx (local access ports),
// dialog/messages.tsx (the App dialog) and inspector/messages.tsx (the inspector and its sandbox traffic).

import { defineMessages } from "@/i18n";

// What the traffic sentences call the connection that carries an App's traffic, and where that traffic enters it.
const viaEn = (owner: string | null) => (owner ? `connection “${owner}”` : "its connection");
const viaZh = (owner: string | null) => (owner ? `連線「${owner}」` : "所屬連線");
const viaJa = (owner: string | null) => (owner ? `接続「${owner}」` : "所属する接続");
const entryEn = (port: number | null) => (port ? `127.0.0.1:${port}` : "the Gateway");
const entryZh = (port: number | null) => (port ? `127.0.0.1:${port}` : "代理埠");
// Japanese puts a space between Latin text and its own, none next to its own words.
const entryJa = (port: number | null) => (port ? ` 127.0.0.1:${port} ` : "ゲートウェイ");

export const m = defineMessages({
  en: {
    /** One managed app, as a column heading. */
    app: "App",
    connection: "Connection",
    gateway: "Gateway",
    executable: "Executable",
    processes: "Processes",
    traffic: "Traffic",
    settings: "Settings",
    args: "Arguments",
    workingDir: "Working directory",
    environment: "Environment variables",
    resourceLimits: "Resource limits",
    needsAttention: "Needs attention",
    loopbackOnly: "This host only",
    noRunningProcess: "No process is running",
    /** Where an App works when no working directory is set. */
    privateHome: "The app's private home directory",
    notApproved: "Not approved yet",
    sameAsApproved: "Same as the approved file",
    restartOnRecovery: "Start again automatically after the core service restarts",
    /** In place of a row's number while the removed row fades out. */
    removedRow: "(removed)",
    list: (parts: readonly string[]) => parts.join(", "),
    labelAndDetail: (label: string, detail: string) => `${label}: ${detail}`,
    /** When the executable was approved, and its size. */
    approvedAt: (when: string, size: string) => `Approved ${when} · ${size}`,
    /** Why a failed App failed, as its state. */
    state: {
      exited: "Exited abnormally",
      outOfMemory: "Memory limit exceeded",
      forcedStop: "Stopped by force",
      stopUnconfirmed: "Stop not confirmed",
      handedOff: "Handed over to another process",
      awaitsApproval: "Executable awaits approval",
      cannotStart: "Cannot start",
    },
    approvalProblem: {
      notApproved: "The executable is not approved yet: check and approve it first",
      changed: "The executable was changed after it was approved: check it and approve it again first",
      /** The problem as a sentence of its own. */
      sentence: (problem: string) => `${problem}.`,
    },
    attention: {
      stopped: (reason: string) => `Stopped: ${reason}`,
      exposed: (count: number) =>
        `Listening on ${count} non-loopback ${count === 1 ? "address" : "addresses"}: other hosts may be able to connect`,
      intentNotStored: "The latest intent cannot be written to disk",
      pendingRevision: (running: number, current: number) =>
        `The running program was started with revision ${running} of the settings; they are now at revision ${current}, which applies after a restart.`,
      settingsChanged: "The settings have changed and apply after a restart",
    },
    /** The inspector's conclusion: what the App's network is now. */
    network: {
      /** `limit`: what the mode does not do (isolation.proxy_env.limit). */
      proxyEnvRunning: (port: number | null, owner: string | null, limit: string) =>
        `The traffic of programs that read these variables enters at ${entryEn(port)} and leaves through ${viaEn(owner)}. ${limit}`,
      noStatus: "The app's state cannot be read right now (the core service is not connected); Stop still works.",
      strictRunning: (owner: string | null) =>
        `The app is in a network namespace of its own, and its only network interface is the tunnel of ${viaEn(owner)}.`,
      enforcedRunning: (port: number | null, owner: string | null) =>
        `The process tree can connect by TCP to ${entryEn(port)} only, and its traffic leaves through ${viaEn(owner)}; every other network is refused.`,
      starting: "Starting: the executable is checked and the isolation applied, then the program runs.",
      stopping: "Stopping: waiting for the whole process tree to exit.",
      stopped: "No process is running; every start checks the executable again.",
    },
    /** What each state filter of the list selects. */
    filter: {
      all: "All managed apps",
      running: "The process tree is running, or is not confirmed to have ended yet",
      attention: "Has a problem, or settings that apply only after a restart",
    },
    isolation: {
      proxy_env: {
        title: "Proxy environment variables only",
        short: "Environment variables",
        text: "Sets ALL_PROXY and HTTP(S)_PROXY to point at the Gateway.",
        limit:
          "The traffic of a program that does not read these variables does not go through the VPN and is not protected.",
      },
      enforced_proxy: {
        title: "Enforced proxy (macOS Seatbelt)",
        short: "Enforced proxy",
        text: "Seatbelt refuses every network except the Gateway; VPN Manager's data and ~/.ssh cannot be read either.",
        limit:
          "Not a complete isolation of the app: connections that system services make on its behalf (the WebKit networking process, certificate checks, for example) are not covered. UDP cannot be used (SOCKS5 UDP included; port forwards deliver TCP only). The app may listen on 127.0.0.1 only: listening on every address (0.0.0.0) gets it stopped within about 2 seconds, so set P2P software to listen on 127.0.0.1 only in its own settings.",
      },
      strict_netns: {
        title: "Strict isolation (Linux netns)",
        short: "Strict isolation",
        text: "Rootless network namespace: the tunnel is the app's only network interface.",
        limit: "Available on Linux only.",
      },
    },
    mode: {
      reading: "Reading the isolation modes this host supports…",
      notReported: "The core service did not report this isolation mode",
      /** Why an App cannot start here: `reason` is the host's own word, when it gave one. */
      unavailable: (mode: string, reason: string | null) =>
        `This host cannot use “${mode}”: ${reason ?? "unknown reason"}`,
    },
    /** Which proxy variables a Gateway of each kind gets; `socks` and `http` are the assignments. */
    proxyVariables: {
      mixed: (socks: string, http: string) => `Sets ${socks} and ${http}.`,
      socks5: (socks: string) => `Sets ${socks}; a SOCKS5 Gateway sets no HTTP proxy variables.`,
      http: (http: string) => `Sets ${http}; an HTTP Gateway does not set ALL_PROXY.`,
    },
    /** What the executable check recognised a program as, and what follows from it. */
    appClass: {
      label: {
        chromium: "Chromium-based browser",
        firefox: "Firefox-based browser",
        gui: "macOS app",
        launcher: "Starts other programs",
      },
      note: {
        chromium: (name: string) =>
          `VPN Manager starts “${name}” with a data directory of the app's own ({app_home}/chromium-data): even while your own “${name}” is running, the start is not handed over to it, and this is a separate browser.`,
        firefox: (name: string) =>
          `VPN Manager starts “${name}” with a profile of the app's own (-profile {app_home}/firefox-profile -no-remote): even while your own “${name}” is running, the start is not handed over to it, and this is a separate browser.`,
        gui: (name: string) =>
          `While “${name}” is already running, this start may be handed straight to the existing, unprotected process; VPN Manager cannot make it start as a separate new process every time, so it cannot use enforced proxy.`,
        launcher: (name: string) =>
          `“${name}” asks the system to start another program: the program that is started is not its child process and is not managed by VPN Manager, so it cannot use enforced proxy.`,
      },
      notEnforceable: {
        launcher: (name: string) =>
          `“${name}” asks the system to start another program: the program that is started is not its child process and is not in VPN Manager's sandbox, so enforced proxy does not reach it. Name the program to run directly; “Proxy environment variables only” can run it, but does not guarantee that its traffic goes through the VPN`,
        gui: (name: string) =>
          `“${name}” is a macOS app, and VPN Manager cannot make it start as a separate new process every time: while it is already running, this start may be handed straight to the existing, unprotected process, and the limits of enforced proxy come to nothing. Apps of this kind cannot use enforced proxy; “Proxy environment variables only” can run it, but does not guarantee that its traffic goes through the VPN`,
      },
      proxyEnvWarning: {
        launcher: (name: string) =>
          `“${name}” asks the system to start another program; the program that is started is not managed by VPN Manager, and its traffic does not necessarily go through the VPN`,
        gui: (name: string) =>
          `While “${name}” is already running, this start may be handed to the existing, unprotected process; proxy environment variables alone never guarantee that traffic goes through the VPN anyway`,
      },
    },
    validation: {
      nameEmpty: "The name cannot be empty",
      connection: "Choose a connection",
      executableEmpty: "Enter the absolute path of the executable",
      executableNotAbsolute: "The executable must be an absolute path (starting with /, without ..)",
      tooManyArgs: (max: number) => `At most ${max} arguments`,
      argTooLong: "An argument has at most 4096 characters",
      portNeedsGateway: "{gateway_port} needs a Gateway to be chosen",
      /** `injected`: the arguments VPN Manager sets for the browser; `arg`: the App's own argument that collides. */
      profileArg: (name: string, injected: string, arg: string) =>
        `VPN Manager sets the data directory of “${name}” (${injected}), so that it always starts as a separate process and is never handed to a browser that is already running; the arguments cannot set ${arg} as well`,
      unknownPlaceholders: (tokens: readonly string[]) =>
        tokens.length === 1
          ? `${tokens.join(", ")} is not a placeholder that gets replaced; it is passed to the program as it is`
          : `${tokens.join(", ")} are not placeholders that get replaced; they are passed to the program as they are`,
      workingDir: "The working directory must be an absolute path (without ..)",
      tooManyEnv: (max: number) => `At most ${max} environment variables`,
      envName: "A name may use only letters, digits and _, and may not start with a digit",
      envReserved: (name: string) => `${name} is set by VPN Manager and cannot be overridden`,
      envRepeated: (name: string) => `${name} is set more than once`,
      envValueTooLong: "A value has at most 8192 characters",
      gateway: "A proxy mode needs a Gateway of the same connection",
      stopGrace: (min: number, max: number) => `Enter ${min}–${max} seconds`,
      tooManyWritable: (max: number) => `At most ${max} writable directories`,
      writablePath: "Must be an absolute path (without .., and not /)",
    },
    actions: {
      /** The name of the approve intent where it is said like start, stop and restart. */
      approveVerb: "Approve the executable",
      /** What a failed or unconfirmed request was meant to do (the notification's subject). */
      intent: {
        start: (name: string) => `Start ${name}`,
        stop: (name: string) => `Stop ${name}`,
        restart: (name: string) => `Restart ${name}`,
        approve: (name: string) => `Approve the executable of ${name}`,
        remove: (name: string) => `Delete ${name}`,
      },
      /** `action`: the name of the intent on its way. */
      waitingFor: (action: string) => `“${action}” is being sent; wait until it is done`,
      approve: "Check and approve the executable",
      approving: "Approving",
      restartNeedsRunning: "Only a running app can be restarted",
      addForward: "Add port forward",
      deleteUnknown: "The state is unknown, so the app cannot be confirmed as stopped",
      deleteRunning: "A running app cannot be deleted: stop it first",
      /** `shown`: the first few forwards' names; `total`: how many there are. */
      forwardsInTheWay: (shown: readonly string[], total: number) =>
        `${total === 1 ? "Port forward" : "Port forwards"} ${shown.map((n) => `“${n}”`).join(", ")}${total > shown.length ? " and others" : ""} still ${total === 1 ? "delivers" : "deliver"} to this app: delete ${total === 1 ? "it" : "them"} first, or point ${total === 1 ? "it" : "them"} at another app`,
      done: {
        started: (name: string) => `Started ${name}`,
        startSent: (name: string) => `Start sent for ${name}`,
        restarted: (name: string) => `Restarted ${name}`,
        restartSent: (name: string) => `Restart sent for ${name}`,
        stopped: (name: string) => `Stopped ${name}`,
        stopSent: (name: string) => `Stop sent for ${name}`,
        approved: (name: string) => `Approved the executable of ${name}`,
        deleted: (name: string) => `Deleted ${name}`,
        updatesWhenConfirmed: "The state updates once it is confirmed.",
        treeExited: "The whole process tree has exited.",
        stopUnconfirmed: "Not every process is confirmed to have exited yet; the state updates once it is.",
        deletedDetail: "Its private directories and output log were deleted too.",
        nothingToRestart: "No app needs a restart",
        nothingToRestartDetail: "They have already restarted or stopped.",
      },
    },
    /** The dialog that compares the approved executable with the file on disk. */
    approve: {
      title: "Approve the current executable",
      description:
        "Every start computes the SHA-256 again; if it differs from the approved one, the app does not start until you confirm the new file.",
      confirm: "Approve this file",
      waitForCheck: "It can be approved once the check is done",
      cannotApprove: "This file cannot be approved",
      configuredPath: "Configured path",
      approved: "Approved",
      /** What the copy button next to the approved digest copies. */
      approvedDigest: "the approved SHA-256",
      currentFile: "Current file",
      unchanged: "The current file is the approved file; it needs no new approval.",
      expectedOnly: "Approve only a change you expect",
      expectedOnlyDetail:
        "You have just updated the program, for example. If you did not replace the file, find out why first and do not approve it.",
    },
    remove: {
      title: (name: string) => `Delete managed app “${name}”?`,
      body: "Its private home directory (the settings, caches and data the program keeps there) and its output log are deleted with it; the executable itself, its connection and its Gateway are not affected.",
    },
    page: {
      description: "Chosen programs use the network through one connection only.",
      helpSummary:
        "VPN Manager starts it with fixed arguments (not through a shell), points it at its Gateway and watches its process tree. While the connection is not ready, its connections through the Gateway are refused and never fall back to the ordinary network.",
      /** `summary`: `helpSummary`, which the full help continues. */
      help: (summary: string) =>
        `${summary} Select an app to see its process tree, the ports it listens on, its output log and the approval of its executable.`,
      add: "Add app",
      readingConnections: "Reading the connections…",
      needsConnection: "Create a connection first, then add the program that should use the network through it",
      loading: "Loading managed apps",
      empty: "No managed apps yet",
      emptyNeedsConnection:
        "Create a connection and its Gateway first, then add the program that should use the network through it.",
      emptyHint:
        "Choose a program and a connection: VPN Manager starts it with fixed arguments, lets it use the network through that connection only, and watches its process tree.",
      listLabel: "Managed app list",
      search: "Search managed apps",
      searchHint: "Name, executable, isolation mode or connection",
      unit: (count: number): string => (count === 1 ? "app" : "apps"),
      /** `time`: when the list shown was read. */
      stale: (time: string) => `Could not update: showing the data of ${time}`,
      noMatch: "No app matches",
      detailsOf: (name: string) => `Details of ${name}`,
      details: "App details",
      notFound: "This app was not found",
      select: "Select an app",
      selectHint: "See its process tree, the ports it listens on, its output log and the approval of its executable.",
      /** Read after a row's process count by assistive technology. */
      processesSuffix: (count: number | null): string => (count === 1 ? " process" : " processes"),
      exposed: (count: number) => `Exposed listeners: ${count}`,
      /** The list's batch action: restart the running Apps whose saved settings wait for a restart. */
      restartPending: {
        none: "No running app has settings waiting to apply",
        label: "Restart apps with pending settings",
        labelCount: (count: number) => `Restart ${count} ${count === 1 ? "app" : "apps"} with pending settings`,
        short: "Restart pending",
        title: (count: number) => `Restart ${count} ${count === 1 ? "app" : "apps"}?`,
        confirm: (count: number) => `Restart ${count} ${count === 1 ? "app" : "apps"}`,
        changed: (names: readonly string[]) =>
          `The settings of ${names.map((n) => `“${n}”`).join(", ")} have changed and apply only after a restart.`,
        effect:
          "A restart ends their whole process trees and starts them again, so their current connections are cut; other apps are not affected.",
      },
    },
    /** The managed-App process trees on the system pages. */
    resources: {
      none: "No managed app is running",
      /** `state`: the tree's run state; `processes`: how many processes it has, when known. */
      summary: (state: string, processes: number | null) =>
        processes === null ? state : `${state}, ${processes} ${processes === 1 ? "process" : "processes"}`,
    },
  },
  "zh-TW": {
    app: "App",
    connection: "連線",
    gateway: "代理埠",
    executable: "執行檔",
    processes: "程序",
    traffic: "流量",
    settings: "設定",
    args: "參數",
    workingDir: "工作目錄",
    environment: "環境變數",
    resourceLimits: "資源上限",
    needsAttention: "需要處理",
    loopbackOnly: "只限本機",
    noRunningProcess: "沒有執行中的程序",
    privateHome: "App 的私有家目錄",
    notApproved: "尚未核准",
    sameAsApproved: "與已核准的檔案相同",
    restartOnRecovery: "核心服務重新啟動後自動再啟動",
    removedRow: "（已移除）",
    list: (parts) => parts.join("、"),
    labelAndDetail: (label, detail) => `${label}：${detail}`,
    approvedAt: (when, size) => `${when} 核准 · ${size}`,
    state: {
      exited: "異常結束",
      outOfMemory: "記憶體超過上限",
      forcedStop: "已被強制停止",
      stopUnconfirmed: "無法確認已停止",
      handedOff: "交給了其他程序",
      awaitsApproval: "執行檔待核准",
      cannotStart: "無法啟動",
    },
    approvalProblem: {
      notApproved: "執行檔尚未核准，請先檢查並核准",
      changed: "執行檔在核准後被修改過，請先檢查並重新核准",
      sentence: (problem) => `${problem}。`,
    },
    attention: {
      stopped: (reason) => `已停止：${reason}`,
      exposed: (count) => `在 ${count} 個非本機位址監聽：其他主機可能連得到`,
      intentNotStored: "最新的操作意圖無法寫入磁碟",
      pendingRevision: (running, current) =>
        `執行中的程式是用第 ${running} 版設定啟動的；目前是第 ${current} 版，重新啟動後才會套用。`,
      settingsChanged: "設定已變更，重新啟動後才會套用",
    },
    network: {
      proxyEnvRunning: (port, owner, limit) => `讀取這些變數的程式經 ${entryZh(port)} 由${viaZh(owner)}送出。${limit}`,
      noStatus: "目前讀不到 App 狀態（核心服務未連線）；停止仍可使用。",
      strictRunning: (owner) => `App 在自己的網路空間裡，唯一的網路介面是${viaZh(owner)}的 tunnel。`,
      enforcedRunning: (port, owner) =>
        `程序樹只能以 TCP 連到 ${entryZh(port)}，由${viaZh(owner)}送出；其他網路一律拒絕。`,
      starting: "正在啟動：先檢查執行檔、套用隔離，再執行程式。",
      stopping: "正在停止，等待整個程序樹結束。",
      stopped: "沒有執行中的程序；每次啟動都會重新檢查執行檔。",
    },
    filter: {
      all: "所有受管 App",
      running: "程序樹正在執行，或還沒確認已結束",
      attention: "有問題，或設定要重新啟動才會套用",
    },
    isolation: {
      proxy_env: {
        title: "只設代理環境變數",
        short: "環境變數",
        text: "設定 ALL_PROXY、HTTP(S)_PROXY 指向代理埠。",
        limit: "不讀取這些變數的程式，流量不經 VPN、不受保護。",
      },
      enforced_proxy: {
        title: "強制代理（macOS Seatbelt）",
        short: "強制代理",
        text: "以 Seatbelt 拒絕代理埠以外的一切網路，也不能讀取 VPN Manager 資料與 ~/.ssh。",
        limit:
          "不是完整的 App 隔離：系統服務代 App 連線（例如 WebKit 網路程序、憑證檢查）不在此限。不能用 UDP（含 SOCKS5 UDP，轉發也只收 TCP）；App 只能在 127.0.0.1 監聽，在所有位址（0.0.0.0）監聽會在約 2 秒內被停止，P2P 軟體請在它的設定裡改成只在 127.0.0.1 監聽。",
      },
      strict_netns: {
        title: "嚴格隔離（Linux netns）",
        short: "嚴格隔離",
        text: "rootless network namespace：App 只有 tunnel 一個網路介面。",
        limit: "只在 Linux 提供。",
      },
    },
    mode: {
      reading: "正在讀取這台主機支援的隔離方式…",
      notReported: "核心服務沒有回報這種隔離方式",
      unavailable: (mode, reason) => `這台主機無法使用「${mode}」：${reason ?? "未知原因"}`,
    },
    proxyVariables: {
      mixed: (socks, http) => `會設定 ${socks} 與 ${http}。`,
      socks5: (socks) => `會設定 ${socks}；SOCKS5 代理埠不設 HTTP 代理變數。`,
      http: (http) => `會設定 ${http}；HTTP 代理埠不設 ALL_PROXY。`,
    },
    appClass: {
      label: {
        chromium: "Chromium 系瀏覽器",
        firefox: "Firefox 系瀏覽器",
        gui: "macOS App",
        launcher: "會啟動其他程式",
      },
      note: {
        chromium: (name) =>
          `VPN Manager 會以 App 自己的資料目錄（{app_home}/chromium-data）啟動「${name}」：就算你自己的「${name}」正在執行，也不會交給它，而是另一個獨立的瀏覽器。`,
        firefox: (name) =>
          `VPN Manager 會以 App 自己的設定檔（-profile {app_home}/firefox-profile -no-remote）啟動「${name}」：就算你自己的「${name}」正在執行，也不會交給它，而是另一個獨立的瀏覽器。`,
        gui: (name) =>
          `「${name}」已在執行時，這次啟動可能直接交給既有、不受保護的程序；VPN Manager 無法讓它一定以獨立的新程序啟動，所以不能使用強制代理。`,
        launcher: (name) =>
          `「${name}」會請系統另外啟動程式：被啟動的程式不是它的子程序，不由 VPN Manager 管理，所以不能使用強制代理。`,
      },
      notEnforceable: {
        launcher: (name) =>
          `「${name}」會請系統另外啟動程式：被啟動的程式不是它的子程序，不在 VPN Manager 的沙箱裡，強制代理管不到它。請直接指定要執行的程式；「只設代理環境變數」可以執行，但不保證流量經過 VPN`,
        gui: (name) =>
          `「${name}」是 macOS App，VPN Manager 無法讓它一定以獨立的新程序啟動：它已在執行時，這次啟動可能直接交給既有、不受保護的程序，強制代理的限制就落空。這類 App 不能使用強制代理；「只設代理環境變數」可以執行，但不保證流量經過 VPN`,
      },
      proxyEnvWarning: {
        launcher: (name) => `「${name}」會請系統另外啟動程式，被啟動的程式不由 VPN Manager 管理，流量也不一定經過 VPN`,
        gui: (name) =>
          `「${name}」已在執行時，這次啟動可能交給既有、不受保護的程序；只設代理環境變數本來就不保證流量經過 VPN`,
      },
    },
    validation: {
      nameEmpty: "名稱不可空白",
      connection: "請選擇連線",
      executableEmpty: "請輸入執行檔的絕對路徑",
      executableNotAbsolute: "執行檔必須是絕對路徑（以 / 開頭，不含 ..）",
      tooManyArgs: (max) => `參數最多 ${max} 個`,
      argTooLong: "每個參數最多 4096 字元",
      portNeedsGateway: "{gateway_port} 需要選擇代理埠",
      profileArg: (name, injected, arg) =>
        `「${name}」的資料目錄由 VPN Manager 指定（${injected}），讓它一定以獨立的程序啟動、不交給已在執行的瀏覽器；參數裡不能再指定 ${arg}`,
      unknownPlaceholders: (tokens) => `${tokens.join("、")} 不是可替換的符號，會原樣傳給程式`,
      workingDir: "工作目錄必須是絕對路徑（不含 ..）",
      tooManyEnv: (max) => `環境變數最多 ${max} 個`,
      envName: "名稱只能用英文字母、數字與 _，且不以數字開頭",
      envReserved: (name) => `${name} 由 VPN Manager 設定，不能覆寫`,
      envRepeated: (name) => `${name} 重複設定`,
      envValueTooLong: "值最多 8192 字元",
      gateway: "代理模式需要選擇同一條連線的代理埠",
      stopGrace: (min, max) => `請輸入 ${min}–${max} 秒`,
      tooManyWritable: (max) => `可寫入的目錄最多 ${max} 個`,
      writablePath: "必須是絕對路徑（不含 ..，不可為 /）",
    },
    actions: {
      approveVerb: "核准執行檔",
      intent: {
        start: (name) => `啟動 ${name}`,
        stop: (name) => `停止 ${name}`,
        restart: (name) => `重新啟動 ${name}`,
        approve: (name) => `核准執行檔 ${name}`,
        remove: (name) => `刪除 ${name}`,
      },
      waitingFor: (action) => `正在送出「${action}」，完成後再操作`,
      approve: "檢查並核准執行檔",
      approving: "核准中",
      restartNeedsRunning: "只有執行中的 App 可以重新啟動",
      addForward: "新增轉發",
      deleteUnknown: "狀態未知，無法確認已停止",
      deleteRunning: "執行中的 App 不能刪除，請先停止",
      forwardsInTheWay: (shown, total) =>
        `轉發${shown.map((n) => `「${n}」`).join("、")}${total > shown.length ? " 等" : ""}仍送到這個 App：先刪除它們，或改送到其他 App`,
      done: {
        started: (name) => `已啟動 ${name}`,
        startSent: (name) => `已送出啟動 ${name}`,
        restarted: (name) => `已重新啟動 ${name}`,
        restartSent: (name) => `已送出重新啟動 ${name}`,
        stopped: (name) => `已停止 ${name}`,
        stopSent: (name) => `已送出停止 ${name}`,
        approved: (name) => `已核准 ${name} 的執行檔`,
        deleted: (name) => `已刪除 ${name}`,
        updatesWhenConfirmed: "狀態會在確認後更新。",
        treeExited: "整個程序樹都已結束。",
        stopUnconfirmed: "尚未確認所有程序都已結束；狀態會在確認後更新。",
        deletedDetail: "它的私有目錄與輸出紀錄也已刪除。",
        nothingToRestart: "沒有需要重新啟動的 App",
        nothingToRestartDetail: "它們已經重新啟動或停止。",
      },
    },
    approve: {
      title: "核准目前的執行檔",
      description: "每次啟動都會重新計算 SHA-256；與核准時不同就不啟動，直到你確認新的檔案。",
      confirm: "核准這個檔案",
      waitForCheck: "檢查完成後才能核准",
      cannotApprove: "這個檔案不能核准",
      configuredPath: "設定的路徑",
      approved: "已核准",
      approvedDigest: "已核准的 SHA-256",
      currentFile: "目前的檔案",
      unchanged: "目前的檔案就是已核准的檔案，不需要重新核准。",
      expectedOnly: "只核准你預期的變更",
      expectedOnlyDetail: "例如你剛更新了這個程式。檔案若不是你換的，請先查明原因，不要核准。",
    },
    remove: {
      title: (name) => `刪除受管 App「${name}」？`,
      body: "它的私有家目錄（程式存在那裡的設定、快取與資料）與輸出紀錄會一起刪除；執行檔本身、所屬連線與代理埠不受影響。",
    },
    page: {
      description: "指定的程式只經某條連線上網。",
      helpSummary:
        "VPN Manager 以固定參數啟動它（不經 shell）、指向所屬代理埠，並監看它的程序樹。連線未就緒時，它經代理埠的連線會被拒絕，不會改走一般網路。",
      help: (summary) => `${summary}選一個 App 查看它的程序樹、監聽的連接埠、輸出紀錄與執行檔核准。`,
      add: "新增 App",
      readingConnections: "正在讀取連線…",
      needsConnection: "先建立一條連線，再新增要經它上網的程式",
      loading: "載入受管 App",
      empty: "還沒有受管 App",
      emptyNeedsConnection: "先建立一條連線與它的代理埠，再新增要經它上網的程式。",
      emptyHint: "指定一個程式與一條連線：VPN Manager 以固定參數啟動它、讓它只經這條連線上網，並監看它的程序樹。",
      listLabel: "受管 App 清單",
      search: "搜尋受管 App",
      searchHint: "名稱、執行檔、隔離方式或連線",
      unit: () => "個 App",
      stale: (time) => `無法更新：顯示的是 ${time} 的資料`,
      noMatch: "沒有符合條件的 App",
      detailsOf: (name) => `${name} 的詳細資料`,
      details: "App 詳細資料",
      notFound: "找不到這個 App",
      select: "選擇一個 App",
      selectHint: "查看它的程序樹、監聽的連接埠、輸出紀錄與執行檔核准。",
      processesSuffix: () => " 個程序",
      exposed: (count) => `對外監聽 ${count}`,
      restartPending: {
        none: "沒有設定待套用的執行中 App",
        label: "重新啟動待套用的 App",
        labelCount: (count) => `重新啟動待套用的 ${count} 個 App`,
        short: "重新啟動待套用",
        title: (count) => `重新啟動 ${count} 個 App？`,
        confirm: (count) => `重新啟動 ${count} 個 App`,
        changed: (names) => `${names.map((n) => `「${n}」`).join("、")}的設定已變更，重新啟動後才會套用。`,
        effect: "重新啟動會結束它們整個程序樹再啟動，它們目前的連線會中斷；其他 App 不受影響。",
      },
    },
    resources: {
      none: "沒有執行中的受管 App",
      summary: (state, processes) => (processes === null ? state : `${state}，${processes} 個程序`),
    },
  },
  ja: {
    app: "アプリ",
    connection: "接続",
    gateway: "ゲートウェイ",
    executable: "実行ファイル",
    processes: "プロセス",
    traffic: "トラフィック",
    settings: "設定",
    args: "引数",
    workingDir: "作業ディレクトリ",
    environment: "環境変数",
    resourceLimits: "リソース上限",
    needsAttention: "要対応",
    loopbackOnly: "このホストのみ",
    noRunningProcess: "実行中のプロセスはありません",
    privateHome: "アプリ専用のホームディレクトリ",
    notApproved: "未承認",
    sameAsApproved: "承認済みのファイルと同じ",
    restartOnRecovery: "コアサービスの再起動後に自動で開始",
    removedRow: "（削除済み）",
    list: (parts) => parts.join("、"),
    labelAndDetail: (label, detail) => `${label}：${detail}`,
    approvedAt: (when, size) => `${when} に承認 · ${size}`,
    state: {
      exited: "異常終了",
      outOfMemory: "メモリ上限を超過",
      forcedStop: "強制停止済み",
      stopUnconfirmed: "停止を確認できません",
      handedOff: "別のプロセスに引き渡し済み",
      awaitsApproval: "実行ファイルの承認待ち",
      cannotStart: "開始できません",
    },
    approvalProblem: {
      notApproved: "実行ファイルはまだ承認されていません。先に確認して承認してください",
      changed: "実行ファイルは承認後に変更されています。先に確認して、もう一度承認してください",
      sentence: (problem) => `${problem}。`,
    },
    attention: {
      stopped: (reason) => `停止：${reason}`,
      exposed: (count) =>
        `ループバック以外の ${count} 個のアドレスで待ち受けています。ほかのホストから接続できる可能性があります`,
      intentNotStored: "最新の操作の意図をディスクに書き込めません",
      pendingRevision: (running, current) =>
        `実行中のプログラムは第 ${running} 版の設定で開始されました。現在は第 ${current} 版で、再起動後に適用されます。`,
      settingsChanged: "設定が変更されました。再起動後に適用されます",
    },
    network: {
      proxyEnvRunning: (port, owner, limit) =>
        `これらの変数を読むプログラムの通信は${entryJa(port)}から入り、${viaJa(owner)}を通って送信されます。${limit}`,
      noStatus: "現在アプリの状態を読み取れません（コアサービスに未接続）。停止は引き続き使えます。",
      strictRunning: (owner) =>
        `アプリは専用のネットワーク名前空間の中にあり、唯一のネットワークインターフェースは${viaJa(owner)}のトンネルです。`,
      enforcedRunning: (port, owner) =>
        `プロセスツリーが TCP で接続できるのは${entryJa(port)}だけで、通信は${viaJa(owner)}を通って送信されます。それ以外のネットワークはすべて拒否されます。`,
      starting: "開始中：実行ファイルを確認し、分離を適用してから、プログラムを実行します。",
      stopping: "停止中：プロセスツリー全体が終了するのを待っています。",
      stopped: "実行中のプロセスはありません。開始のたびに実行ファイルを確認し直します。",
    },
    filter: {
      all: "すべての管理対象アプリ",
      running: "プロセスツリーが実行中、またはまだ終了を確認できていない",
      attention: "問題がある、または再起動しないと適用されない設定がある",
    },
    isolation: {
      proxy_env: {
        title: "プロキシ環境変数の設定のみ",
        short: "環境変数",
        text: "ALL_PROXY と HTTP(S)_PROXY がゲートウェイを指すように設定します。",
        limit: "これらの変数を読まないプログラムの通信は VPN を経由せず、保護されません。",
      },
      enforced_proxy: {
        title: "強制プロキシ（macOS Seatbelt）",
        short: "強制プロキシ",
        text: "Seatbelt でゲートウェイ以外のネットワークをすべて拒否します。VPN Manager のデータと ~/.ssh も読み取れません。",
        limit:
          "アプリの完全な分離ではありません。システムサービスがアプリの代わりに行う接続（WebKit のネットワークプロセス、証明書の確認など）は対象外です。UDP は使えません（SOCKS5 UDP を含みます。ポート転送も TCP しか受け付けません）。アプリが待ち受けできるのは 127.0.0.1 だけで、すべてのアドレス（0.0.0.0）で待ち受けると約 2 秒以内に停止されます。P2P ソフトウェアは、その設定で 127.0.0.1 だけで待ち受けるように変更してください。",
      },
      strict_netns: {
        title: "厳格な分離（Linux netns）",
        short: "厳格な分離",
        text: "rootless network namespace：アプリのネットワークインターフェースはトンネルだけです。",
        limit: "Linux でのみ利用できます。",
      },
    },
    mode: {
      reading: "このホストが対応している分離方式を読み込んでいます…",
      notReported: "コアサービスがこの分離方式を報告していません",
      unavailable: (mode, reason) => `このホストでは「${mode}」を使えません：${reason ?? "原因不明"}`,
    },
    proxyVariables: {
      mixed: (socks, http) => `${socks} と ${http} を設定します。`,
      socks5: (socks) => `${socks} を設定します。SOCKS5 ゲートウェイは HTTP プロキシ変数を設定しません。`,
      http: (http) => `${http} を設定します。HTTP ゲートウェイは ALL_PROXY を設定しません。`,
    },
    appClass: {
      label: {
        chromium: "Chromium 系ブラウザー",
        firefox: "Firefox 系ブラウザー",
        gui: "macOS アプリ",
        launcher: "ほかのプログラムを起動",
      },
      note: {
        chromium: (name) =>
          `VPN Manager は「${name}」をアプリ専用のデータディレクトリ（{app_home}/chromium-data）で起動します。自分の「${name}」が実行中でも起動がそちらに引き渡されることはなく、別の独立したブラウザーになります。`,
        firefox: (name) =>
          `VPN Manager は「${name}」をアプリ専用のプロファイル（-profile {app_home}/firefox-profile -no-remote）で起動します。自分の「${name}」が実行中でも起動がそちらに引き渡されることはなく、別の独立したブラウザーになります。`,
        gui: (name) =>
          `「${name}」がすでに実行中のときは、今回の起動が保護されていない既存のプロセスにそのまま引き渡されることがあります。VPN Manager は毎回独立した新しいプロセスとして起動させることができないため、強制プロキシは使えません。`,
        launcher: (name) =>
          `「${name}」はシステムにほかのプログラムの起動を依頼します。起動されたプログラムはその子プロセスではなく、VPN Manager の管理下にもないため、強制プロキシは使えません。`,
      },
      notEnforceable: {
        launcher: (name) =>
          `「${name}」はシステムにほかのプログラムの起動を依頼します。起動されたプログラムはその子プロセスではなく、VPN Manager のサンドボックスの中にもないため、強制プロキシが及びません。実行するプログラムを直接指定してください。「プロキシ環境変数の設定のみ」なら実行できますが、通信が VPN を経由する保証はありません`,
        gui: (name) =>
          `「${name}」は macOS アプリで、VPN Manager は毎回独立した新しいプロセスとして起動させることができません。すでに実行中のときは、今回の起動が保護されていない既存のプロセスにそのまま引き渡されることがあり、強制プロキシの制限が意味を失います。この種類のアプリは強制プロキシを使えません。「プロキシ環境変数の設定のみ」なら実行できますが、通信が VPN を経由する保証はありません`,
      },
      proxyEnvWarning: {
        launcher: (name) =>
          `「${name}」はシステムにほかのプログラムの起動を依頼します。起動されたプログラムは VPN Manager の管理下になく、その通信が VPN を経由するとは限りません`,
        gui: (name) =>
          `「${name}」がすでに実行中のときは、今回の起動が保護されていない既存のプロセスに引き渡されることがあります。そもそもプロキシ環境変数の設定だけでは、通信が VPN を経由する保証はありません`,
      },
    },
    validation: {
      nameEmpty: "名前は空にできません",
      connection: "接続を選択してください",
      executableEmpty: "実行ファイルの絶対パスを入力してください",
      executableNotAbsolute: "実行ファイルは絶対パスにしてください（/ で始まり、.. を含まないもの）",
      tooManyArgs: (max) => `引数は最大 ${max} 個です`,
      argTooLong: "引数は 1 つにつき最大 4096 文字です",
      portNeedsGateway: "{gateway_port} を使うにはゲートウェイを選択してください",
      profileArg: (name, injected, arg) =>
        `「${name}」のデータディレクトリは VPN Manager が指定します（${injected}）。これにより常に独立したプロセスとして起動し、実行中のブラウザーに引き渡されることはありません。引数で ${arg} を指定することはできません`,
      unknownPlaceholders: (tokens) =>
        `${tokens.join("、")} は置き換えられるプレースホルダーではなく、そのままプログラムに渡されます`,
      workingDir: "作業ディレクトリは絶対パスにしてください（.. を含まないもの）",
      tooManyEnv: (max) => `環境変数は最大 ${max} 個です`,
      envName: "名前に使えるのは英字、数字、_ だけで、数字で始めることはできません",
      envReserved: (name) => `${name} は VPN Manager が設定するため、上書きできません`,
      envRepeated: (name) => `${name} が重複しています`,
      envValueTooLong: "値は最大 8192 文字です",
      gateway: "プロキシ方式では同じ接続のゲートウェイを選択してください",
      stopGrace: (min, max) => `${min}–${max} 秒で入力してください`,
      tooManyWritable: (max) => `書き込み可能なディレクトリは最大 ${max} 個です`,
      writablePath: "絶対パスにしてください（.. を含まず、/ 以外のもの）",
    },
    actions: {
      approveVerb: "実行ファイルを承認",
      intent: {
        start: (name) => `${name} の開始`,
        stop: (name) => `${name} の停止`,
        restart: (name) => `${name} の再起動`,
        approve: (name) => `${name} の実行ファイルの承認`,
        remove: (name) => `${name} の削除`,
      },
      waitingFor: (action) => `「${action}」を送信中です。完了してから操作してください`,
      approve: "実行ファイルを確認して承認",
      approving: "承認中",
      restartNeedsRunning: "再起動できるのは実行中のアプリだけです",
      addForward: "ポート転送を追加",
      deleteUnknown: "状態が不明なため、停止を確認できません",
      deleteRunning: "実行中のアプリは削除できません。先に停止してください",
      forwardsInTheWay: (shown, total) =>
        `ポート転送${shown.map((n) => `「${n}」`).join("、")}${total > shown.length ? "など" : ""}がまだこのアプリに転送しています。先にそれらを削除するか、転送先を別のアプリに変更してください`,
      done: {
        started: (name) => `${name} を開始しました`,
        startSent: (name) => `${name} の開始を送信しました`,
        restarted: (name) => `${name} を再起動しました`,
        restartSent: (name) => `${name} の再起動を送信しました`,
        stopped: (name) => `${name} を停止しました`,
        stopSent: (name) => `${name} の停止を送信しました`,
        approved: (name) => `${name} の実行ファイルを承認しました`,
        deleted: (name) => `${name} を削除しました`,
        updatesWhenConfirmed: "確認でき次第、状態が更新されます。",
        treeExited: "プロセスツリー全体が終了しました。",
        stopUnconfirmed: "すべてのプロセスの終了はまだ確認できていません。確認でき次第、状態が更新されます。",
        deletedDetail: "専用ディレクトリと出力ログも削除しました。",
        nothingToRestart: "再起動が必要なアプリはありません",
        nothingToRestartDetail: "すでに再起動または停止しています。",
      },
    },
    approve: {
      title: "現在の実行ファイルを承認",
      description:
        "開始のたびに SHA-256 を計算し直します。承認時と異なる場合は、新しいファイルを確認するまでアプリを開始しません。",
      confirm: "このファイルを承認",
      waitForCheck: "確認が終わると承認できます",
      cannotApprove: "このファイルは承認できません",
      configuredPath: "設定したパス",
      approved: "承認済み",
      approvedDigest: "承認済みの SHA-256",
      currentFile: "現在のファイル",
      unchanged: "現在のファイルは承認済みのファイルと同じです。承認し直す必要はありません。",
      expectedOnly: "想定どおりの変更だけを承認してください",
      expectedOnlyDetail:
        "例えば、このプログラムを更新したばかりの場合です。自分でファイルを置き換えていないなら、承認せずに先に原因を調べてください。",
    },
    remove: {
      title: (name) => `管理対象アプリ「${name}」を削除しますか？`,
      body: "専用のホームディレクトリ（プログラムがそこに保存した設定、キャッシュ、データ）と出力ログも一緒に削除されます。実行ファイル自体、所属する接続、ゲートウェイには影響しません。",
    },
    page: {
      description: "指定したプログラムを特定の接続だけで通信させます。",
      helpSummary:
        "VPN Manager は固定の引数でプログラムを起動し（シェルを介しません）、所属するゲートウェイを指すように設定して、そのプロセスツリーを監視します。接続の準備ができていない間、ゲートウェイ経由の接続は拒否され、通常のネットワークに切り替わることはありません。",
      help: (summary) =>
        `${summary}アプリを選ぶと、そのプロセスツリー、待ち受けポート、出力ログ、実行ファイルの承認を確認できます。`,
      add: "アプリを追加",
      readingConnections: "接続を読み込んでいます…",
      needsConnection: "先に接続を作成してから、それを通じて通信させるプログラムを追加してください",
      loading: "管理対象アプリを読み込み中",
      empty: "管理対象アプリはまだありません",
      emptyNeedsConnection:
        "先に接続とそのゲートウェイを作成してから、それを通じて通信させるプログラムを追加してください。",
      emptyHint:
        "プログラムと接続を 1 つずつ指定します。VPN Manager は固定の引数でプログラムを起動し、その接続だけで通信させて、プロセスツリーを監視します。",
      listLabel: "管理対象アプリの一覧",
      search: "管理対象アプリを検索",
      searchHint: "名前、実行ファイル、分離方式、接続",
      unit: () => "件のアプリ",
      stale: (time) => `更新できません：${time} 時点のデータを表示しています`,
      noMatch: "条件に一致するアプリはありません",
      detailsOf: (name) => `${name} の詳細`,
      details: "アプリの詳細",
      notFound: "このアプリが見つかりません",
      select: "アプリを選択",
      selectHint: "プロセスツリー、待ち受けポート、出力ログ、実行ファイルの承認を確認できます。",
      processesSuffix: () => " 個のプロセス",
      exposed: (count) => `外部で待ち受け ${count}`,
      restartPending: {
        none: "設定が適用待ちの実行中のアプリはありません",
        label: "適用待ちのアプリを再起動",
        labelCount: (count) => `適用待ちの ${count} 件のアプリを再起動`,
        short: "適用待ちを再起動",
        title: (count) => `${count} 件のアプリを再起動しますか？`,
        confirm: (count) => `${count} 件のアプリを再起動`,
        changed: (names) =>
          `${names.map((n) => `「${n}」`).join("、")}の設定が変更されており、再起動後に適用されます。`,
        effect:
          "再起動するとプロセスツリー全体を終了してから開始し直すため、現在の接続は切断されます。ほかのアプリには影響しません。",
      },
    },
    resources: {
      none: "実行中の管理対象アプリはありません",
      summary: (state, processes) => (processes === null ? state : `${state}、${processes} 個のプロセス`),
    },
  },
});
