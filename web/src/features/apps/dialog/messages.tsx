// Text of the managed-App dialog (new and edit): its fields, hints and notices, the executable check, the argument,
// environment and writable-directory editors, the resource limits and recovery. A sub-area of the Managed apps page
// (../messages.ts), kept apart for size; its validation messages are the page's (`validation`). A .tsx: one sentence
// carries markup (src/i18n/README.md).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    addTitle: "Add managed app",
    editTitle: (name: string) => `Edit ${name}`,
    description:
      "VPN Manager starts this program with fixed arguments (not through a shell), lets its network use the chosen connection only, and watches its process tree.",
    create: "Create app",
    created: (name: string) => `Created ${name}`,
    saved: (name: string) => `Saved ${name}`,
    savedWhileRunning: "The running program is not affected; the settings apply after a restart.",
    namePlaceholder: "For example: work browser",
    chooseConnection: "Choose a connection…",
    isolationMode: "Network isolation mode",
    /** Under an isolation mode or a resource limit this host cannot provide. */
    notOnThisHost: (reason: string | null) => `Not available on this host: ${reason ?? "unknown reason"}`,
    hostCannotRun: (mode: string) => `This host cannot run “${mode}”`,
    cannotEnforce: "This program cannot use enforced proxy",
    chooseGateway: "Choose a Gateway…",
    /** `kind`: the Gateway's protocol as the Gateway pages name it. */
    gatewayOption: (port: number, name: string, kind: string, enabled: boolean) =>
      `127.0.0.1:${port} · ${name} (${kind})${enabled ? "" : " · disabled"}`,
    noGateway: "This connection has no Gateway yet; a proxy mode needs one.",
    connectionFirst: "Choose a connection first.",
    addGateway: "Add Gateway",
    executable: {
      waitingForCheck: "The file is being checked; submit again once that is done.",
      keepsApproval:
        "The approval is kept while the path stays the same; a change to the file's content is approved again on the app's page.",
      hint: "An absolute path; a macOS .app runs its main executable. Saving approves the file shown below (SHA-256).",
      placeholder: "/Applications/Firefox.app or /usr/bin/curl",
      cannotApprove: "This file cannot be approved; see the note below",
      checking: "Checking the file…",
      checkFailed: "Could not check this file",
      canRun: "Can run",
      bundleMain: "Main executable of the .app",
      differs: "Differs from the approved file",
      /** Before the path of the file that runs. */
      resolved: "Actually runs: ",
    },
    /** `n` in the names below: the row's number, or `removedRow`. */
    args: {
      /** `port` and `home`: the two placeholders, each already an element. */
      help: (port: ReactNode, home: ReactNode): ReactNode => (
        <>
          No shell is involved: every row is one argument, and spaces, quotes and $VAR reach the program as they are.{" "}
          {port} (the Gateway's port number) and {home} (the app's private home directory, for a browser's profile
          directory, say) can be used.
        </>
      ),
      item: (n: string) => `Argument ${n}`,
      move: {
        up: (n: string) => `Move argument ${n} up`,
        down: (n: string) => `Move argument ${n} down`,
      },
      remove: (n: string) => `Remove argument ${n}`,
      add: "Add argument",
      /** Above the command line as it will run; `injected`: how many arguments VPN Manager puts first. */
      preview: (injected: number) =>
        `Actually runs${injected ? ` (VPN Manager puts ${injected} ${injected === 1 ? "argument" : "arguments"} first: the browser's own data directory)` : ""}`,
      /** What stands for {app_home} in that command line while the App has no home directory yet. */
      previewHome: "the app's private home directory",
    },
    alreadyFirst: "Already the first",
    alreadyLast: "Already the last",
    atMost: (max: number) => `At most ${max}`,
    workingDirHint: "Left empty, the app's private home directory is used.",
    env: {
      help: "HOME, TMPDIR and the proxy variables are set by VPN Manager and cannot be overridden; no other variable is inherited from VPN Manager.",
      noSecrets: "Do not put passwords, tokens or keys here",
      noSecretsDetail: "Environment variables are stored in plain text and are shown on the app's page.",
      name: (n: string) => `Name of environment variable ${n}`,
      value: (n: string) => `Value of environment variable ${n}`,
      valuePlaceholder: "Value",
      remove: (n: string) => `Remove environment variable ${n}`,
      add: "Add environment variable",
    },
    confineWrites: "Confine writes",
    confineWritesHint:
      "When on, the app can write only to its own private directories (HOME, TMPDIR), /dev and the directories listed below; everything else is read-only (Linux Landlock). Recommended for programs that keep data safe, such as wallets and nodes. If this host's kernel does not support it, the app does not start.",
    writable: {
      title: "Writable directories",
      enforcedHelp:
        "Under enforced proxy, the app can write only to its own private directories and the directories listed here; VPN Manager's data directory and ~/.ssh can never be read or written.",
      strictHelp:
        "The folders the app writes its data to, the data directory of a node or a wallet, for example; their subfolders are writable too. VPN Manager's data directory and ~/.ssh can never be read or written.",
      item: (n: string) => `Writable directory ${n}`,
      remove: (n: string) => `Remove writable directory ${n}`,
      add: "Add directory",
    },
    limits: {
      help: "Empty means unlimited. A limit that is set is always in force when the app starts; if it cannot be, the app does not start. A limit this host cannot enforce cannot be set.",
      /** A limit's name with its unit. */
      field: (label: string, unit: string) => (unit ? `${label} (${unit})` : label),
      unavailable: "Not available",
    },
    stopGrace: "Stop grace period (seconds)",
    stopGraceHint: (min: number, max: number, byDefault: number) =>
      `On a stop, a restart, or when the core service stops, the app gets at most this long after the termination signal before it is killed (${min}–${max} seconds, ${byDefault} by default). Set it longer where a wallet or a database needs time to save, for example 300 seconds for a blockchain node.`,
    restartOnRecoveryHint:
      "After VPN Manager's core service (manager) restarts or is upgraded, or the computer reboots, this app is started again unless “Stop” was pressed, also when its last run ended by itself or ended together with the sandbox. When off, it is not started again, and the reason is shown.",
  },
  "zh-TW": {
    addTitle: "新增受管 App",
    editTitle: (name) => `編輯 ${name}`,
    description: "VPN Manager 以固定的參數啟動這個程式（不經 shell），讓它的網路只經指定的連線，並監看它的程序樹。",
    create: "建立 App",
    created: (name) => `已建立 ${name}`,
    saved: (name) => `已儲存 ${name}`,
    savedWhileRunning: "執行中的程式不受影響，重新啟動後套用。",
    namePlaceholder: "例如：工作用瀏覽器",
    chooseConnection: "選擇連線…",
    isolationMode: "網路隔離方式",
    notOnThisHost: (reason) => `此主機無法使用：${reason ?? "未知原因"}`,
    hostCannotRun: (mode) => `這台主機無法執行「${mode}」`,
    cannotEnforce: "這個程式不能使用強制代理",
    chooseGateway: "選擇代理埠…",
    gatewayOption: (port, name, kind, enabled) => `127.0.0.1:${port} · ${name}（${kind}）${enabled ? "" : " · 已停用"}`,
    noGateway: "這條連線還沒有代理埠；代理模式需要一個。",
    connectionFirst: "先選擇連線。",
    addGateway: "新增代理埠",
    executable: {
      waitingForCheck: "正在檢查檔案，完成後再送出一次。",
      keepsApproval: "路徑不變時保留原本的核准；檔案內容變更要在 App 頁面重新核准。",
      hint: "絕對路徑；macOS 的 .app 會執行它的主執行檔。儲存時核准下面顯示的檔案（SHA-256）。",
      placeholder: "/Applications/Firefox.app 或 /usr/bin/curl",
      cannotApprove: "這個檔案不能核准，請看下方說明",
      checking: "檢查檔案中…",
      checkFailed: "無法檢查這個檔案",
      canRun: "可以執行",
      bundleMain: ".app 的主執行檔",
      differs: "與已核准的檔案不同",
      resolved: "實際執行：",
    },
    args: {
      help: (port, home) => (
        <>
          不經 shell：每一列就是一個參數，空白、引號與 $VAR 都會原樣傳給程式。可用 {port}（代理埠號）與 {home}（App
          的私有家目錄，例如瀏覽器的設定檔目錄）。
        </>
      ),
      item: (n) => `參數 ${n}`,
      move: {
        up: (n) => `參數 ${n} 上移`,
        down: (n) => `參數 ${n} 下移`,
      },
      remove: (n) => `移除參數 ${n}`,
      add: "新增參數",
      preview: (injected) =>
        `實際執行${injected ? `（VPN Manager 在前面加上 ${injected} 個參數：瀏覽器自己的資料目錄）` : ""}`,
      previewHome: "App 的私有家目錄",
    },
    alreadyFirst: "已經是第一個",
    alreadyLast: "已經是最後一個",
    atMost: (max) => `最多 ${max} 個`,
    workingDirHint: "留空時使用 App 的私有家目錄。",
    env: {
      help: "HOME、TMPDIR 與代理變數由 VPN Manager 設定，不能覆寫；其他變數不會從 VPN Manager 繼承。",
      noSecrets: "不要在這裡放密碼、token 或金鑰",
      noSecretsDetail: "環境變數以明文儲存，也會顯示在 App 頁面。",
      name: (n) => `環境變數 ${n} 名稱`,
      value: (n) => `環境變數 ${n} 的值`,
      valuePlaceholder: "值",
      remove: (n) => `移除環境變數 ${n}`,
      add: "新增環境變數",
    },
    confineWrites: "限制寫入位置",
    confineWritesHint:
      "開啟後 App 只能寫入它自己的私有目錄（HOME、TMPDIR）、/dev 與下面列出的目錄，其他地方只能讀（Linux Landlock）；錢包、節點這類保管資料的程式建議開啟。這台主機的核心不支援時，App 不會啟動。",
    writable: {
      title: "可寫入的目錄",
      enforcedHelp:
        "強制代理下，App 只能寫入自己的私有目錄與這裡列出的目錄；VPN Manager 的資料目錄與 ~/.ssh 永遠不能讀寫。",
      strictHelp:
        "App 寫入資料的資料夾，例如節點或錢包的資料目錄；子資料夾一併可寫。VPN Manager 的資料目錄與 ~/.ssh 永遠不能讀寫。",
      item: (n) => `可寫入的目錄 ${n}`,
      remove: (n) => `移除可寫入的目錄 ${n}`,
      add: "新增目錄",
    },
    limits: {
      help: "留空表示不限。設定的上限在 App 啟動時一定生效，做不到就不啟動；這台主機無法執行的上限不能設定。",
      field: (label, unit) => (unit ? `${label}（${unit}）` : label),
      unavailable: "無法使用",
    },
    stopGrace: "停止前等待（秒）",
    stopGraceHint: (min, max, byDefault) =>
      `停止、重新啟動，或核心服務停止時，App 收到結束訊號後最多等這麼久，才會被強制結束（${min}–${max} 秒，預設 ${byDefault}）。錢包、資料庫需要時間存檔時請設長一點，例如區塊鏈節點 300 秒。`,
    restartOnRecoveryHint:
      "VPN Manager 的核心服務（manager）重新啟動、升級或電腦重新開機後，只要沒有按過「停止」就再啟動這個 App——包括上次執行自己結束、或隨 sandbox 一起結束；關閉時不再啟動，並說明原因。",
  },
  ja: {
    addTitle: "管理対象アプリを追加",
    editTitle: (name) => `${name} を編集`,
    description:
      "VPN Manager はこのプログラムを固定の引数で起動し（シェルを介しません）、指定した接続だけで通信させて、プロセスツリーを監視します。",
    create: "アプリを作成",
    created: (name) => `${name} を作成しました`,
    saved: (name) => `${name} を保存しました`,
    savedWhileRunning: "実行中のプログラムには影響しません。再起動後に適用されます。",
    namePlaceholder: "例：業務用ブラウザー",
    chooseConnection: "接続を選択…",
    isolationMode: "ネットワークの分離方式",
    notOnThisHost: (reason) => `このホストでは使えません：${reason ?? "原因不明"}`,
    hostCannotRun: (mode) => `このホストでは「${mode}」を実行できません`,
    cannotEnforce: "このプログラムは強制プロキシを使えません",
    chooseGateway: "ゲートウェイを選択…",
    gatewayOption: (port, name, kind, enabled) => `127.0.0.1:${port} · ${name}（${kind}）${enabled ? "" : " · 無効"}`,
    noGateway: "この接続にはまだゲートウェイがありません。プロキシ方式には 1 つ必要です。",
    connectionFirst: "先に接続を選択してください。",
    addGateway: "ゲートウェイを追加",
    executable: {
      waitingForCheck: "ファイルを確認しています。終わったらもう一度送信してください。",
      keepsApproval:
        "パスが変わらなければ元の承認を保持します。ファイルの内容が変わった場合は、アプリのページで承認し直してください。",
      hint: "絶対パス。macOS の .app はそのメインの実行ファイルを実行します。保存すると、下に表示されたファイル（SHA-256）を承認します。",
      placeholder: "/Applications/Firefox.app または /usr/bin/curl",
      cannotApprove: "このファイルは承認できません。下の説明を確認してください",
      checking: "ファイルを確認中…",
      checkFailed: "このファイルを確認できませんでした",
      canRun: "実行可能",
      bundleMain: ".app のメイン実行ファイル",
      differs: "承認済みのファイルと異なります",
      resolved: "実際に実行されるファイル：",
    },
    args: {
      help: (port, home) => (
        <>
          シェルは介しません。各行が 1 つの引数で、スペース、引用符、$VAR はそのままプログラムに渡されます。
          {port}（ゲートウェイのポート番号）と {home}
          （アプリ専用のホームディレクトリ。ブラウザーのプロファイルディレクトリの指定などに）を使えます。
        </>
      ),
      item: (n) => `引数 ${n}`,
      move: {
        up: (n) => `引数 ${n} を上へ移動`,
        down: (n) => `引数 ${n} を下へ移動`,
      },
      remove: (n) => `引数 ${n} を削除`,
      add: "引数を追加",
      preview: (injected) =>
        `実際に実行されるコマンド${injected ? `（VPN Manager が先頭に ${injected} 個の引数を追加：ブラウザー専用のデータディレクトリ）` : ""}`,
      previewHome: "アプリ専用のホームディレクトリ",
    },
    alreadyFirst: "すでに先頭です",
    alreadyLast: "すでに末尾です",
    atMost: (max) => `最大 ${max} 個`,
    workingDirHint: "空欄の場合はアプリ専用のホームディレクトリを使います。",
    env: {
      help: "HOME、TMPDIR、プロキシ変数は VPN Manager が設定し、上書きできません。それ以外の変数は VPN Manager から引き継がれません。",
      noSecrets: "パスワード、トークン、鍵をここに入れないでください",
      noSecretsDetail: "環境変数は平文で保存され、アプリのページにも表示されます。",
      name: (n) => `環境変数 ${n} の名前`,
      value: (n) => `環境変数 ${n} の値`,
      valuePlaceholder: "値",
      remove: (n) => `環境変数 ${n} を削除`,
      add: "環境変数を追加",
    },
    confineWrites: "書き込み先を制限",
    confineWritesHint:
      "オンにすると、アプリが書き込めるのは専用ディレクトリ（HOME、TMPDIR）、/dev、下に指定したディレクトリだけになり、それ以外は読み取り専用になります（Linux Landlock）。ウォレットやノードなど、データを保管するプログラムにはオンを推奨します。このホストのカーネルが対応していない場合、アプリは開始しません。",
    writable: {
      title: "書き込み可能なディレクトリ",
      enforcedHelp:
        "強制プロキシでは、アプリが書き込めるのは専用ディレクトリとここに指定したディレクトリだけです。VPN Manager のデータディレクトリと ~/.ssh は決して読み書きできません。",
      strictHelp:
        "アプリがデータを書き込むフォルダー。例えばノードやウォレットのデータディレクトリです。サブフォルダーも書き込み可能になります。VPN Manager のデータディレクトリと ~/.ssh は決して読み書きできません。",
      item: (n) => `書き込み可能なディレクトリ ${n}`,
      remove: (n) => `書き込み可能なディレクトリ ${n} を削除`,
      add: "ディレクトリを追加",
    },
    limits: {
      help: "空欄は無制限です。設定した上限はアプリの開始時に必ず適用され、適用できなければ開始しません。このホストで適用できない上限は設定できません。",
      field: (label, unit) => (unit ? `${label}（${unit}）` : label),
      unavailable: "利用不可",
    },
    stopGrace: "停止の猶予時間（秒）",
    stopGraceHint: (min, max, byDefault) =>
      `停止、再起動、またはコアサービスの停止時は、アプリに終了シグナルを送ってから最大でこの時間待ち、その後に強制終了します（${min}–${max} 秒、既定は ${byDefault}）。ウォレットやデータベースの保存に時間がかかる場合は長めに設定してください。例えばブロックチェーンのノードなら 300 秒です。`,
    restartOnRecoveryHint:
      "VPN Manager のコアサービス（manager）の再起動やアップグレード、またはコンピューターの再起動の後、「停止」を押していなければこのアプリを再び開始します。前回の実行が自ら終了した場合や、サンドボックスと一緒に終了した場合も含みます。オフにすると開始せず、その理由を表示します。",
  },
});
