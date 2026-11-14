// Text of the SSH hosts page: the entries VPN Manager writes to vpn-manager.conf, the Include line in ~/.ssh/config
// that makes ssh read them, and the read-only listing of the user's own ssh config. Option names (Include,
// ProxyCommand, ControlPath …), commands, paths and file names are not translated. The page's title is the section
// name (components/shell/messages.ts, `nav.ssh`).

import type { ReactNode } from "react";
import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** Marks the words of a sentence that carry its warning; the page supplies the markup. */
type Emphasis = (text: string) => ReactNode;

export const m = defineMessages({
  en: {
    /** The page's primary action; sentences quote it by this name. */
    addHost: "Add SSH host",
    actionsOf: (alias: string) => `Actions for ${alias}`,
    moreActionsOf: (alias: string) => `More actions for ${alias}`,
    page: {
      description: "Reach chosen SSH hosts through the VPN; VPN Manager writes only its own vpn-manager.conf.",
      help: "~/.ssh/config is changed only once, when you press “Add Include”, and it is backed up first. Hosts that go through a Gateway use vpnctl as their ProxyCommand: when the connection is not ready or the security profile refuses, ssh fails and says why; it never falls back to the ordinary network. An existing host (a block in ~/.ssh/config) can get just the route, with every other setting as before.",
      helpText: "~/.ssh/config is changed only once, when you press “Add Include”, and it is backed up first.",
      listLabel: "SSH host list",
      settingsOf: (alias: string) => `Settings of ${alias}`,
      allHosts: "All SSH hosts",
      crumbRoute: (alias: string) => `Route ${alias} through the VPN`,
      readingStatus: "Reading the SSH configuration",
    },
    list: {
      managed: "Managed by VPN Manager",
      managedHosts: "Hosts managed by VPN Manager",
      loadingHosts: "Loading SSH hosts",
      noEntries: "No entries yet: add a host, or route an existing host below through the VPN.",
      existing: "~/.ssh/config (read-only)",
      readingConfig: "Reading ~/.ssh/config",
      existingHosts: "Hosts in ~/.ssh/config",
      viaVpn: "Through the VPN",
      wildcard: "Wildcard",
      noConfig: "No ~/.ssh/config",
      noBlocks: "No host blocks",
      overlayViaVpn: "Existing host · through the VPN",
      hostViaVpn: (host: string | null) => `${host} · through the VPN`,
      hostDirect: (host: string | null) => `${host} · direct connection`,
    },
    /** Why ssh does not use an entry as configured right now. */
    issue: {
      configUnreadable: "~/.ssh/config cannot be read, so this cannot be confirmed",
      overlayLate: "The Include is not at the top: it may connect directly",
      overlayMissing: "The Include is not in effect: it connects directly now",
      hostMissing: "The Include is not in effect: ssh does not use this entry",
      gatewayDisabled: "The Gateway is disabled: connections will fail",
      notInEffect: "Not in effect",
      overlayFix:
        "This entry takes effect only through the Include at the top of ~/.ssh/config; see the top of the page for the fix.",
      hostFix: "ssh uses this entry only once it reads vpn-manager.conf; see the top of the page for the fix.",
    },
    /** The status strip: where the Include stands, whether vpn-manager.conf is current, and the fix for each. */
    file: {
      action: {
        include: "Add Include",
        apply: "Write vpn-manager.conf",
        overwrite: "Replace with VPN Manager's content",
      },
      /** The same actions as what a failure is reported about. */
      intent: {
        include: "Add Include",
        apply: "Write vpn-manager.conf",
        overwrite: "Replace with VPN Manager's content",
      },
      working: "Working",
      otherRunning: "Another file action is running; wait until it is done",
      includeLine: "Include line",
      includeAdded: "Include added",
      configBackedUp: (backup: string) => `The previous ~/.ssh/config was backed up as ${backup}.`,
      configCreated: "There was no ~/.ssh/config, so a new file was created.",
      overwritten: "Replaced with VPN Manager's content",
      contentBackedUp: (backup: string) => `The previous content was backed up as ${backup}.`,
      applied: "vpn-manager.conf written",
      unavailable: "SSH Manager cannot apply anything right now",
      configLinked:
        "~/.ssh/config is a symbolic link (managed by dotfiles, for example): VPN Manager does not change it, so adjust it by hand.",
      late: {
        title: "The Include is not at the top",
        body: (strong: Emphasis): ReactNode => (
          <>
            Earlier settings or other Include lines take precedence: entries that route an existing host through the VPN
            may stop working and {strong("connect directly")}. This line has to be the first setting in the file (adding
            it makes a backup first and puts it at the top):
          </>
        ),
      },
      missing: {
        overlaysDirect: (aliases: readonly string[]) =>
          `The Include is gone: ${listEn.format(aliases)} ${aliases.length === 1 ? "connects" : "connect"} directly now`,
        noConfig: "There is no ~/.ssh/config yet",
        notIncluded: "~/.ssh/config does not load VPN Manager's hosts yet",
        createsConfig:
          "Adding it creates ~/.ssh/config with this line at the top of the file; only then do the hosts here take effect:",
        backsUpConfig:
          "Adding it backs up ~/.ssh/config first and puts this line at the top of the file; only then do the hosts here take effect:",
      },
      unsafe: {
        /** `problem` is the service's own wording of what is wrong with the file. */
        title: (problem: string | null) =>
          problem === null ? "~/.ssh/config cannot be read safely" : `~/.ssh/config: ${problem}`,
        body: (aliases: readonly string[]) =>
          `VPN Manager neither reads nor changes it${
            aliases.length
              ? `, and cannot confirm whether ${listEn.format(aliases)} ${aliases.length === 1 ? "goes" : "go"} through the VPN`
              : ""
          }. After fixing it, make sure the file starts with:`,
      },
      modified: {
        title: "vpn-manager.conf was edited by hand; writing is paused",
        body: "To avoid overwriting your changes, what you change here is not written to the file for now.",
        current: "Current file content",
      },
      unsafeFile: {
        title: "vpn-manager.conf cannot be written safely",
        body: "It is a symbolic link, does not belong to the current user, or can be written by others.",
      },
      lastWriteFailed: "The last write did not finish",
      stale: {
        title: "vpn-manager.conf is not up to date yet",
        body: "The saved entries or ~/.ssh/config have changed; ssh still uses the old content of the file.",
      },
      inPlace: "The Include is at the top",
      inPlaceAndCurrent: "The Include is at the top and vpn-manager.conf is up to date",
      overwriteConfirm: {
        title: "Replace vpn-manager.conf with VPN Manager's content?",
        confirm: "Back up and replace",
        body: "The current file is saved as a backup first, then the content VPN Manager generates is written; your ~/.ssh/config is not affected.",
        after: "Editing the file by hand afterwards pauses writing again.",
      },
    },
    /** What the probe through the Gateway found. */
    test: {
      reached: "The Gateway reaches this host's SSH service",
      unreachable: "The Gateway cannot reach this host",
    },
    editor: {
      routeTitle: (alias: string) => `Route “${alias}” through the VPN`,
      viaGateway: (port: number | string) => `Through Gateway :${port}`,
      direct: "Direct connection",
      existingHost: "Existing host",
      managedHost: "VPN Manager host",
      idLabel: "entry ID",
      savedNote: "Saving writes vpn-manager.conf; see the top of the page for its state.",
      newNote: "Adding it writes vpn-manager.conf.",
      add: "Add",
      adding: "Adding",
      saved: (alias: string) => `Saved ${alias}`,
      added: (alias: string) => `Added ${alias}`,
      overlay: {
        title: "Depends on the Include at the top of ~/.ssh/config",
        body: (strong: Emphasis): ReactNode => (
          <>
            This entry writes only the route (ProxyCommand, ControlPath) and the keepalive interval; every other setting
            still comes from your ~/.ssh/config. If the Include line is removed, this host falls back to a{" "}
            {strong("direct connection")} without any error; when it must go through the VPN only, use “Add SSH host”
            and give it a new alias.
          </>
        ),
        replacesProxy: "The existing ProxyJump or ProxyCommand is replaced.",
      },
    },
    host: {
      title: "Host",
      alias: "Alias",
      aliasHint: "Used as ssh <alias>",
      otherNames: "Names that also go through the VPN",
      nameList: (names: readonly string[]) => names.join(", "),
      address: "Host address",
      configLine: (line: number) => `~/.ssh/config, line ${line}`,
      user: "User",
      sshDefault: "(ssh default)",
      port: "Port",
      identityFile: "Key file",
      identityFilePlaceholder: "~/.ssh/id_ed25519 (empty: the ssh default)",
      identitiesOnly: "Use only this key (IdentitiesOnly)",
      identitiesOnlyOn: "The other keys in ssh-agent are no longer tried.",
      identitiesOnlyNeedsKey: "Choose a key file first to turn this on.",
    },
    route: {
      title: "Route",
      via: "Through",
      viaHint:
        "The Gateway resolves the host name inside the tunnel; while the connection is not ready ssh fails and never connects directly.",
      directOption: "Direct connection (not through the VPN)",
      chooseGateway: "Choose a Gateway…",
      /** One Gateway of the list: its name, port, the connection it belongs to and its kind. */
      gatewayOption: (name: string, port: number, connection: string | undefined, kind: string, enabled: boolean) =>
        `${name} · :${port} · ${connection ?? "connection"} (${kind})${enabled ? "" : " (disabled)"}`,
      interval: "Keepalive interval (seconds)",
      intervalViaVpn: "10–240; keeps an idle connection from being dropped",
      intervalDirect: "Optional, 10–3600",
      gatewayDisabled: "This Gateway is disabled",
      gatewayDisabledBody: "ssh connections through it fail and say why; they never fall back to the ordinary network.",
      openGateway: "Open the Gateway",
      /** The connection the chosen Gateway belongs to, with its state. */
      owner: (name: string | undefined, state: string | undefined) =>
        `Connection: ${name ?? "—"} (${state ?? "state unknown"})`,
    },
    preview: {
      title: "What is written to vpn-manager.conf",
      /** Stand-ins for values the draft does not have yet, inside the previewed block. */
      alias: "<alias>",
      port: "<port>",
      controlPath: (withCommand: boolean) =>
        `ControlPath keeps a connection through the VPN from reusing a shared connection (ControlMaster) made another way.${
          withCommand ? " To see the settings ssh actually uses, run this in a terminal:" : ""
        }`,
      command: "command",
    },
    /** A block of the user's own ~/.ssh/config. */
    existing: {
      description: (line: number) => `Line ${line} · read-only: VPN Manager does not change this block`,
      routedBy: (alias: string) => `The VPN Manager entry “${alias}” routes it through the VPN.`,
      wildcardNote: "A wildcard host cannot go through the VPN on its own.",
      routeNote: "Creates an entry that writes only the route; every other setting still comes from this block.",
      routed: "VPN Manager already routes it through the VPN",
      wildcard: "A wildcard host cannot go through the VPN on its own",
      wildcardBody: "Use “Add SSH host” to create an entry for the destination you need.",
      sameAsAlias: "(same as the alias)",
      jump: "Jump host",
      jumpSet: "ProxyJump or ProxyCommand is set",
    },
    empty: {
      notInConfig: "~/.ssh/config has no such host",
      notInConfigBody: "It may have been renamed or removed.",
      notFound: "Entry not found",
      notFoundBody: "It may have been removed.",
      choose: "Choose a host",
      intro: "Reach chosen SSH hosts through the VPN",
      body: "Hosts that go through a Gateway use vpnctl as their ProxyCommand: when the connection is not ready or the security profile refuses, ssh fails and says why; it never falls back to the ordinary network.",
    },
    actions: {
      test: "Test connection",
      testing: "Testing",
      testDirect: "A host that connects directly does not go through a Gateway, so there is no route to test",
      testUnsaved: "Save first, then test",
      remove: "Remove",
      removing: "Removing",
      removeSending: "“Remove” is being sent; wait until it is done",
      openEntry: "Open entry",
      route: "Route it through the VPN",
      wildcard:
        "A wildcard host cannot go through the VPN on its own: use “Add SSH host” to create an entry for the destination you need",
    },
    /** What a failure is reported about. */
    intent: {
      test: "Test connection",
      remove: (alias: string) => `Remove ${alias}`,
    },
    remove: {
      title: (alias: string) => `Remove “${alias}”?`,
      overlay: (alias: string) =>
        `“${alias}” goes back to its own settings in ~/.ssh/config and no longer goes through the VPN; your ~/.ssh/config is not changed.`,
      host: (alias: string) =>
        `“${alias}” is removed from vpn-manager.conf, and ssh ${alias} will no longer find this host. Other entries are not affected.`,
      last: "This is the last entry; vpn-manager.conf keeps only its explanation.",
      removed: (alias: string) => `Removed ${alias}`,
    },
    validation: {
      localName: "A local host name cannot be reached through the VPN",
      mdnsName: "An mDNS (.local) name exists only on the local network and cannot be reached through the VPN",
      unreachableAddress: "A loopback, link-local or multicast address cannot be reached through the VPN",
      alias: "An alias may use only lower-case letters, digits and . _ -, and must start with a letter or digit",
      hostRequired: "Enter the host address",
      hostInvalid:
        "The host address must be a domain name or a complete IP address (short forms such as 127.1 are not accepted)",
      privateAddress:
        "A private address can be reached through the VPN only when this connection's security profile allows that network; otherwise the Gateway refuses it and never falls back to the ordinary network",
      bareName: "A name without a domain usually resolves only on the local network and is not found through the VPN",
      user: "A user name may use only letters, digits and . _ - @",
      identityFile: "Must start with ~/ or / and contain no spaces, quotes, % or ..",
      identitiesOnly: "Choose a key file first",
      aliasResolvable:
        "When the alias itself can be resolved, ssh connects directly once the Include stops working; an alias without a . is recommended",
      gatewayRequired: "An entry for an existing host is there to route it through the VPN: choose a Gateway",
      intervalRequired: "A keepalive interval (10–240 seconds) is required when going through the VPN",
      intervalViaVpn: "Must be between 10 and 240 seconds when going through the VPN",
      intervalDirect: "10–3600 seconds",
    },
  },
  "zh-TW": {
    addHost: "新增 SSH 主機",
    actionsOf: (alias) => `${alias} 的操作`,
    moreActionsOf: (alias) => `${alias} 的更多操作`,
    page: {
      description: "讓指定的 SSH 主機經 VPN 連線；VPN Manager 只寫自己的 vpn-manager.conf。",
      help: "~/.ssh/config 只在你按下「加入 Include」時修改一次，而且會先備份。經代理埠的主機以 vpnctl 作為 ProxyCommand：連線未就緒或被安全設定拒絕時，ssh 會失敗並說明原因，不會改走一般網路。既有主機（~/.ssh/config 裡的區塊）可以只加上連線方式，其餘設定照舊。",
      helpText: "~/.ssh/config 只在你按下「加入 Include」時修改一次，而且會先備份。",
      listLabel: "SSH 主機清單",
      settingsOf: (alias) => `${alias} 的設定`,
      allHosts: "所有 SSH 主機",
      crumbRoute: (alias) => `讓 ${alias} 經 VPN`,
      readingStatus: "讀取 SSH 設定",
    },
    list: {
      managed: "VPN Manager 管理",
      managedHosts: "VPN Manager 管理的主機",
      loadingHosts: "載入 SSH 主機",
      noEntries: "還沒有項目；新增一台主機，或讓下方的既有主機經 VPN。",
      existing: "~/.ssh/config（唯讀）",
      readingConfig: "讀取 ~/.ssh/config",
      existingHosts: "~/.ssh/config 的主機",
      viaVpn: "經 VPN",
      wildcard: "萬用字元",
      noConfig: "沒有 ~/.ssh/config",
      noBlocks: "沒有主機區塊",
      overlayViaVpn: "既有主機 · 經 VPN",
      hostViaVpn: (host) => `${host} · 經 VPN`,
      hostDirect: (host) => `${host} · 直接連線`,
    },
    issue: {
      configUnreadable: "無法讀取 ~/.ssh/config，無法確認",
      overlayLate: "Include 不在最前面，可能直接連線",
      overlayMissing: "Include 未生效，目前直接連線",
      hostMissing: "Include 未生效，ssh 不會使用這個項目",
      gatewayDisabled: "代理埠已停用，連線會失敗",
      notInEffect: "未生效",
      overlayFix: "這個項目要靠 ~/.ssh/config 最前面的 Include 才會生效；修正方式見頁首。",
      hostFix: "ssh 要讀到 vpn-manager.conf 才會使用這個項目；修正方式見頁首。",
    },
    file: {
      action: {
        include: "加入 Include",
        apply: "寫入 vpn-manager.conf",
        overwrite: "以 VPN Manager 的內容取代",
      },
      intent: {
        include: "加入 Include",
        apply: "寫入 vpn-manager.conf",
        overwrite: "以 VPN Manager 的內容取代",
      },
      working: "處理中",
      otherRunning: "正在處理另一個檔案操作，完成後再操作",
      includeLine: "Include 行",
      includeAdded: "已加入 Include",
      configBackedUp: (backup) => `原本的 ~/.ssh/config 已備份為 ${backup}。`,
      configCreated: "原本沒有 ~/.ssh/config，已建立新檔。",
      overwritten: "已以 VPN Manager 的內容取代",
      contentBackedUp: (backup) => `原本的內容已備份為 ${backup}。`,
      applied: "已寫入 vpn-manager.conf",
      unavailable: "SSH Manager 目前無法套用",
      configLinked: "~/.ssh/config 是符號連結（例如由 dotfiles 管理），VPN Manager 不會修改它，請手動調整。",
      late: {
        title: "Include 不在最前面",
        body: (strong) => (
          <>
            前面的設定或其他 Include 會優先生效：讓既有主機經 VPN 的項目可能失效並{strong("直接連線")}
            。這一行需要是檔案的第一個設定（加入時會先備份，並把它放到最前面）：
          </>
        ),
      },
      missing: {
        overlaysDirect: (aliases) => `Include 不見了：${aliases.join("、")} 目前會直接連線`,
        noConfig: "還沒有 ~/.ssh/config",
        notIncluded: "~/.ssh/config 還沒有載入 VPN Manager 的主機",
        createsConfig: "加入時會建立 ~/.ssh/config，在檔案最前面加入這一行，這裡的主機才會生效：",
        backsUpConfig: "加入時會先備份 ~/.ssh/config，在檔案最前面加入這一行，這裡的主機才會生效：",
      },
      unsafe: {
        title: (problem) => `~/.ssh/config ${problem ?? "無法安全讀取"}`,
        body: (aliases) =>
          `VPN Manager 不會讀取或修改它${
            aliases.length ? `，也無法確認 ${aliases.join("、")} 是否經 VPN` : ""
          }。修正後，請確認檔案最前面有：`,
      },
      modified: {
        title: "vpn-manager.conf 已被手動修改，暫停寫入",
        body: "為避免覆蓋你的變更，這裡的修改暫時不會寫入檔案。",
        current: "目前檔案內容",
      },
      unsafeFile: {
        title: "vpn-manager.conf 無法安全寫入",
        body: "它是符號連結、不屬於目前使用者，或可被他人寫入。",
      },
      lastWriteFailed: "上次寫入沒有完成",
      stale: {
        title: "vpn-manager.conf 還不是最新內容",
        body: "儲存的項目或 ~/.ssh/config 已變更，ssh 目前仍使用檔案裡的舊內容。",
      },
      inPlace: "Include 在最前面",
      inPlaceAndCurrent: "Include 在最前面，vpn-manager.conf 已是最新內容",
      overwriteConfirm: {
        title: "以 VPN Manager 的內容取代 vpn-manager.conf？",
        confirm: "備份並取代",
        body: "目前的檔案會先另存為備份，再寫入 VPN Manager 產生的內容；你的 ~/.ssh/config 不受影響。",
        after: "之後在檔案中的手動修改會再次暫停寫入。",
      },
    },
    test: {
      reached: "代理埠連得到這台主機的 SSH 服務",
      unreachable: "代理埠連不到這台主機",
    },
    editor: {
      routeTitle: (alias) => `讓「${alias}」經 VPN`,
      viaGateway: (port) => `經代理埠 :${port}`,
      direct: "直接連線",
      existingHost: "既有主機",
      managedHost: "VPN Manager 主機",
      idLabel: "項目 ID",
      savedNote: "儲存後寫入 vpn-manager.conf；狀態見頁首。",
      newNote: "加入後寫入 vpn-manager.conf。",
      add: "加入",
      adding: "加入中",
      saved: (alias) => `已儲存 ${alias}`,
      added: (alias) => `已加入 ${alias}`,
      overlay: {
        title: "依賴 ~/.ssh/config 最前面的 Include",
        body: (strong) => (
          <>
            這個項目只寫入連線方式（ProxyCommand、ControlPath）與保活間隔，其餘設定仍來自你的 ~/.ssh/config。Include
            行若被移除，這台主機會改為{strong("直接連線")}而不會報錯；需要保證只經 VPN 時，請改用「新增 SSH
            主機」並取一個新的別名。
          </>
        ),
        replacesProxy: "原本的 ProxyJump／ProxyCommand 會被取代。",
      },
    },
    host: {
      title: "主機",
      alias: "別名",
      aliasHint: "ssh <別名> 時使用",
      otherNames: "一併經 VPN 的名稱",
      nameList: (names) => names.join("、"),
      address: "主機位址",
      configLine: (line) => `~/.ssh/config 第 ${line} 行`,
      user: "使用者",
      sshDefault: "（ssh 預設）",
      port: "埠",
      identityFile: "金鑰檔",
      identityFilePlaceholder: "~/.ssh/id_ed25519（留空使用 ssh 預設）",
      identitiesOnly: "只用這把金鑰（IdentitiesOnly）",
      identitiesOnlyOn: "不再嘗試 ssh-agent 中的其他金鑰。",
      identitiesOnlyNeedsKey: "先指定金鑰檔才能開啟。",
    },
    route: {
      title: "連線方式",
      via: "經過",
      viaHint: "主機名稱交給代理埠在 tunnel 內解析；連線未就緒時 ssh 會失敗，不會直連。",
      directOption: "直接連線（不經 VPN）",
      chooseGateway: "選擇代理埠…",
      gatewayOption: (name, port, connection, kind, enabled) =>
        `${name} · :${port} · ${connection ?? "連線"}（${kind}）${enabled ? "" : "（已停用）"}`,
      interval: "保活間隔（秒）",
      intervalViaVpn: "10–240，讓閒置的連線不被中斷",
      intervalDirect: "選填，10–3600",
      gatewayDisabled: "這個代理埠已停用",
      gatewayDisabledBody: "經它的 ssh 連線會失敗並說明原因，不會改走一般網路。",
      openGateway: "開啟代理埠",
      owner: (name, state) => `所屬連線：${name ?? "—"}（${state ?? "狀態未知"}）`,
    },
    preview: {
      title: "寫入 vpn-manager.conf 的內容",
      alias: "<別名>",
      port: "<埠>",
      controlPath: (withCommand) =>
        `ControlPath 讓經 VPN 的連線不會沿用其他方式建立的共用連線（ControlMaster）。${
          withCommand ? "要確認 ssh 實際採用的設定，可自行在終端機執行：" : ""
        }`,
      command: "指令",
    },
    existing: {
      description: (line) => `第 ${line} 行 · 唯讀，VPN Manager 不會修改這個區塊`,
      routedBy: (alias) => `由 VPN Manager 的項目「${alias}」讓它經 VPN。`,
      wildcardNote: "萬用字元主機無法單獨經 VPN。",
      routeNote: "建立一個只寫入連線方式的項目；其餘設定仍來自這個區塊。",
      routed: "已經由 VPN Manager 讓它經 VPN",
      wildcard: "萬用字元主機無法單獨經 VPN",
      wildcardBody: "請改用「新增 SSH 主機」為需要的目的地建立項目。",
      sameAsAlias: "（同別名）",
      jump: "跳板",
      jumpSet: "已設定 ProxyJump／ProxyCommand",
    },
    empty: {
      notInConfig: "~/.ssh/config 沒有這台主機",
      notInConfigBody: "它可能已被改名或移除。",
      notFound: "找不到這個項目",
      notFoundBody: "它可能已被移除。",
      choose: "選擇一台主機",
      intro: "讓指定的 SSH 主機經 VPN 連線",
      body: "經代理埠的主機以 vpnctl 作為 ProxyCommand：連線未就緒或被安全設定拒絕時，ssh 會失敗並說明原因，不會改走一般網路。",
    },
    actions: {
      test: "測試連線",
      testing: "測試中",
      testDirect: "直接連線的主機不經代理埠，沒有可以測試的路徑",
      testUnsaved: "先儲存再測試",
      remove: "移除",
      removing: "移除中",
      removeSending: "正在送出「移除」，完成後再操作",
      openEntry: "開啟項目",
      route: "讓它經 VPN",
      wildcard: "萬用字元主機無法單獨經 VPN：請改用「新增 SSH 主機」為需要的目的地建立項目",
    },
    intent: {
      test: "測試連線",
      remove: (alias) => `移除 ${alias}`,
    },
    remove: {
      title: (alias) => `移除「${alias}」？`,
      overlay: (alias) => `「${alias}」會恢復為 ~/.ssh/config 原本的設定，不再經 VPN；你的 ~/.ssh/config 不會被修改。`,
      host: (alias) => `vpn-manager.conf 中的「${alias}」會被移除，ssh ${alias} 將找不到這台主機。其他項目不受影響。`,
      last: "這是最後一個項目，vpn-manager.conf 只會留下說明。",
      removed: (alias) => `已移除 ${alias}`,
    },
    validation: {
      localName: "本機名稱無法經 VPN 連線",
      mdnsName: "mDNS（.local）名稱只存在區網，無法經 VPN 連線",
      unreachableAddress: "loopback、link-local 或 multicast 位址無法經 VPN 到達",
      alias: "別名只能使用小寫英文字母、數字與 . _ -，並以字母或數字開頭",
      hostRequired: "請輸入主機位址",
      hostInvalid: "主機位址必須是網域名稱或完整的 IP 位址（不接受 127.1 這類簡寫）",
      privateAddress: "私有位址只有在這條連線的安全設定允許該網段時才能經 VPN 到達；否則代理埠會拒絕，不會改走一般網路",
      bareName: "沒有網域的名稱通常只在區網可解析，經 VPN 時會找不到",
      user: "使用者名稱只能使用英文字母、數字與 . _ - @",
      identityFile: "必須以 ~/ 或 / 開頭，且不含空白、引號、% 或 ..",
      identitiesOnly: "需要先指定金鑰檔",
      aliasResolvable: "別名本身可被解析時，Include 失效後 ssh 會直接連線；建議使用不含 . 的別名",
      gatewayRequired: "既有主機項目用來讓它經 VPN，請選擇代理埠",
      intervalRequired: "經 VPN 時需要保活間隔（10–240 秒）",
      intervalViaVpn: "經 VPN 時必須介於 10 與 240 秒",
      intervalDirect: "10–3600 秒",
    },
  },
  ja: {
    addHost: "SSH ホストを追加",
    actionsOf: (alias) => `${alias} の操作`,
    moreActionsOf: (alias) => `${alias} のその他の操作`,
    page: {
      description:
        "指定した SSH ホストに VPN 経由で接続します。VPN Manager が書き込むのは自身の vpn-manager.conf だけです。",
      help: "~/.ssh/config を変更するのは「Include を追加」を押したときの一度だけで、先にバックアップを取ります。ゲートウェイを経由するホストは vpnctl を ProxyCommand として使います。接続の準備ができていないときやセキュリティ設定に拒否されたとき、ssh は理由を示して失敗し、通常のネットワークには切り替わりません。既存のホスト（~/.ssh/config 内のブロック）には接続方法だけを追加でき、ほかの設定はそのままです。",
      helpText: "~/.ssh/config を変更するのは「Include を追加」を押したときの一度だけで、先にバックアップを取ります。",
      listLabel: "SSH ホスト一覧",
      settingsOf: (alias) => `${alias} の設定`,
      allHosts: "すべての SSH ホスト",
      crumbRoute: (alias) => `${alias} を VPN 経由にする`,
      readingStatus: "SSH の設定を読み込んでいます",
    },
    list: {
      managed: "VPN Manager が管理",
      managedHosts: "VPN Manager が管理するホスト",
      loadingHosts: "SSH ホストを読み込んでいます",
      noEntries: "項目はまだありません。ホストを追加するか、下の既存のホストを VPN 経由にしてください。",
      existing: "~/.ssh/config（読み取り専用）",
      readingConfig: "~/.ssh/config を読み込んでいます",
      existingHosts: "~/.ssh/config のホスト",
      viaVpn: "VPN 経由",
      wildcard: "ワイルドカード",
      noConfig: "~/.ssh/config がありません",
      noBlocks: "ホストのブロックがありません",
      overlayViaVpn: "既存のホスト · VPN 経由",
      hostViaVpn: (host) => `${host} · VPN 経由`,
      hostDirect: (host) => `${host} · 直接接続`,
    },
    issue: {
      configUnreadable: "~/.ssh/config を読み取れないため、確認できません",
      overlayLate: "Include が先頭にないため、直接接続になる可能性があります",
      overlayMissing: "Include が有効になっておらず、現在は直接接続です",
      hostMissing: "Include が有効になっておらず、ssh はこの項目を使いません",
      gatewayDisabled: "ゲートウェイが無効のため、接続は失敗します",
      notInEffect: "未反映",
      overlayFix:
        "この項目は ~/.ssh/config の先頭にある Include によって有効になります。修正方法はページ上部を確認してください。",
      hostFix:
        "ssh は vpn-manager.conf を読み込めたときだけこの項目を使います。修正方法はページ上部を確認してください。",
    },
    file: {
      action: {
        include: "Include を追加",
        apply: "vpn-manager.conf に書き込む",
        overwrite: "VPN Manager の内容で置き換える",
      },
      intent: {
        include: "Include の追加",
        apply: "vpn-manager.conf への書き込み",
        overwrite: "VPN Manager の内容での置き換え",
      },
      working: "処理中",
      otherRunning: "別のファイル操作を処理中です。完了してから操作してください",
      includeLine: "Include 行",
      includeAdded: "Include を追加しました",
      configBackedUp: (backup) => `元の ~/.ssh/config を ${backup} としてバックアップしました。`,
      configCreated: "~/.ssh/config がなかったため、新しく作成しました。",
      overwritten: "VPN Manager の内容で置き換えました",
      contentBackedUp: (backup) => `元の内容を ${backup} としてバックアップしました。`,
      applied: "vpn-manager.conf に書き込みました",
      unavailable: "SSH Manager は現在、適用できません",
      configLinked:
        "~/.ssh/config はシンボリックリンクです（dotfiles で管理している場合など）。VPN Manager は変更しないため、手動で調整してください。",
      late: {
        title: "Include が先頭にありません",
        body: (strong) => (
          <>
            先にある設定やほかの Include が優先されます。既存のホストを VPN 経由にする項目が効かなくなり、
            {strong("直接接続")}
            になる可能性があります。この行はファイルの最初の設定である必要があります（追加するときは先にバックアップを取り、先頭に置きます）：
          </>
        ),
      },
      missing: {
        overlaysDirect: (aliases) => `Include がなくなりました：${aliases.join("、")} は現在、直接接続になります`,
        noConfig: "~/.ssh/config がまだありません",
        notIncluded: "~/.ssh/config はまだ VPN Manager のホストを読み込んでいません",
        createsConfig:
          "追加すると ~/.ssh/config を作成し、ファイルの先頭にこの行を入れます。これでここのホストが有効になります：",
        backsUpConfig:
          "追加すると先に ~/.ssh/config をバックアップし、ファイルの先頭にこの行を入れます。これでここのホストが有効になります：",
      },
      unsafe: {
        title: (problem) => (problem === null ? "~/.ssh/config は安全に読み取れません" : `~/.ssh/config：${problem}`),
        body: (aliases) =>
          `VPN Manager はこのファイルを読み取りも変更もしません${
            aliases.length ? `。${aliases.join("、")} が VPN を経由しているかどうかも確認できません` : ""
          }。修正したら、ファイルの先頭に次の行があることを確認してください：`,
      },
      modified: {
        title: "vpn-manager.conf が手動で変更されたため、書き込みを一時停止しています",
        body: "変更を上書きしないよう、ここでの変更は当面ファイルに書き込みません。",
        current: "現在のファイルの内容",
      },
      unsafeFile: {
        title: "vpn-manager.conf に安全に書き込めません",
        body: "シンボリックリンクであるか、現在のユーザーの所有でないか、ほかのユーザーが書き込める状態です。",
      },
      lastWriteFailed: "前回の書き込みが完了しませんでした",
      stale: {
        title: "vpn-manager.conf はまだ最新の内容ではありません",
        body: "保存した項目または ~/.ssh/config が変更されました。ssh は今もファイルの古い内容を使っています。",
      },
      inPlace: "Include は先頭にあります",
      inPlaceAndCurrent: "Include は先頭にあり、vpn-manager.conf は最新の内容です",
      overwriteConfirm: {
        title: "vpn-manager.conf を VPN Manager の内容で置き換えますか？",
        confirm: "バックアップして置き換える",
        body: "現在のファイルをバックアップとして保存してから、VPN Manager が生成した内容を書き込みます。~/.ssh/config には影響しません。",
        after: "その後にファイルを手動で変更すると、再び書き込みが一時停止します。",
      },
    },
    test: {
      reached: "ゲートウェイからこのホストの SSH サービスに接続できます",
      unreachable: "ゲートウェイからこのホストに接続できません",
    },
    editor: {
      routeTitle: (alias) => `「${alias}」を VPN 経由にする`,
      viaGateway: (port) => `ゲートウェイ :${port} 経由`,
      direct: "直接接続",
      existingHost: "既存のホスト",
      managedHost: "VPN Manager のホスト",
      idLabel: "項目 ID",
      savedNote: "保存すると vpn-manager.conf に書き込みます。状態はページ上部で確認できます。",
      newNote: "追加すると vpn-manager.conf に書き込みます。",
      add: "追加",
      adding: "追加中",
      saved: (alias) => `${alias} を保存しました`,
      added: (alias) => `${alias} を追加しました`,
      overlay: {
        title: "~/.ssh/config の先頭にある Include に依存します",
        body: (strong) => (
          <>
            この項目が書き込むのは接続方法（ProxyCommand、ControlPath）とキープアライブ間隔だけで、ほかの設定は引き続き
            ~/.ssh/config のものを使います。Include 行が削除されると、このホストはエラーにならずに
            {strong("直接接続")}
            に切り替わります。必ず VPN だけを経由させたい場合は、「SSH
            ホストを追加」で新しいエイリアスを付けてください。
          </>
        ),
        replacesProxy: "元の ProxyJump／ProxyCommand は置き換えられます。",
      },
    },
    host: {
      title: "ホスト",
      alias: "エイリアス",
      aliasHint: "ssh <エイリアス> で使います",
      otherNames: "あわせて VPN 経由になる名前",
      nameList: (names) => names.join("、"),
      address: "ホストアドレス",
      configLine: (line) => `~/.ssh/config の ${line} 行目`,
      user: "ユーザー",
      sshDefault: "（ssh の既定値）",
      port: "ポート",
      identityFile: "鍵ファイル",
      identityFilePlaceholder: "~/.ssh/id_ed25519（空欄なら ssh の既定値）",
      identitiesOnly: "この鍵だけを使う（IdentitiesOnly）",
      identitiesOnlyOn: "ssh-agent にあるほかの鍵は試しません。",
      identitiesOnlyNeedsKey: "先に鍵ファイルを指定するとオンにできます。",
    },
    route: {
      title: "接続方法",
      via: "経由",
      viaHint:
        "ホスト名はゲートウェイがトンネル内で名前解決します。接続の準備ができていないとき ssh は失敗し、直接接続はしません。",
      directOption: "直接接続（VPN を経由しない）",
      chooseGateway: "ゲートウェイを選択…",
      gatewayOption: (name, port, connection, kind, enabled) =>
        `${name} · :${port} · ${connection ?? "接続"}（${kind}）${enabled ? "" : "（無効）"}`,
      interval: "キープアライブ間隔（秒）",
      intervalViaVpn: "10–240。アイドル状態の接続が切断されないようにします",
      intervalDirect: "任意、10–3600",
      gatewayDisabled: "このゲートウェイは無効です",
      gatewayDisabledBody:
        "このゲートウェイを経由する ssh 接続は理由を示して失敗し、通常のネットワークには切り替わりません。",
      openGateway: "ゲートウェイを開く",
      owner: (name, state) => `所属する接続：${name ?? "—"}（${state ?? "状態不明"}）`,
    },
    preview: {
      title: "vpn-manager.conf に書き込む内容",
      alias: "<エイリアス>",
      port: "<ポート>",
      controlPath: (withCommand) =>
        `ControlPath により、VPN 経由の接続がほかの方法で確立された共有接続（ControlMaster）を使い回すことはありません。${
          withCommand ? "ssh が実際に使う設定を確認するには、ターミナルで次のコマンドを実行してください：" : ""
        }`,
      command: "コマンド",
    },
    existing: {
      description: (line) => `${line} 行目 · 読み取り専用。VPN Manager はこのブロックを変更しません`,
      routedBy: (alias) => `VPN Manager の項目「${alias}」によって VPN 経由になっています。`,
      wildcardNote: "ワイルドカードのホストは単独では VPN 経由にできません。",
      routeNote: "接続方法だけを書き込む項目を作成します。ほかの設定は引き続きこのブロックのものを使います。",
      routed: "すでに VPN Manager によって VPN 経由になっています",
      wildcard: "ワイルドカードのホストは単独では VPN 経由にできません",
      wildcardBody: "「SSH ホストを追加」で必要な宛先の項目を作成してください。",
      sameAsAlias: "（エイリアスと同じ）",
      jump: "踏み台",
      jumpSet: "ProxyJump／ProxyCommand を設定済み",
    },
    empty: {
      notInConfig: "~/.ssh/config にこのホストはありません",
      notInConfigBody: "名前が変更されたか、削除された可能性があります。",
      notFound: "この項目が見つかりません",
      notFoundBody: "削除された可能性があります。",
      choose: "ホストを選択してください",
      intro: "指定した SSH ホストに VPN 経由で接続する",
      body: "ゲートウェイを経由するホストは vpnctl を ProxyCommand として使います。接続の準備ができていないときやセキュリティ設定に拒否されたとき、ssh は理由を示して失敗し、通常のネットワークには切り替わりません。",
    },
    actions: {
      test: "接続テスト",
      testing: "テスト中",
      testDirect: "直接接続のホストはゲートウェイを経由しないため、テストできる経路がありません",
      testUnsaved: "保存してからテストしてください",
      remove: "削除",
      removing: "削除中",
      removeSending: "「削除」を送信中です。完了してから操作してください",
      openEntry: "項目を開く",
      route: "VPN 経由にする",
      wildcard:
        "ワイルドカードのホストは単独では VPN 経由にできません。「SSH ホストを追加」で必要な宛先の項目を作成してください",
    },
    intent: {
      test: "接続テスト",
      remove: (alias) => `${alias} の削除`,
    },
    remove: {
      title: (alias) => `「${alias}」を削除しますか？`,
      overlay: (alias) =>
        `「${alias}」は ~/.ssh/config の元の設定に戻り、VPN を経由しなくなります。~/.ssh/config は変更されません。`,
      host: (alias) =>
        `vpn-manager.conf の「${alias}」が削除され、ssh ${alias} ではこのホストが見つからなくなります。ほかの項目には影響しません。`,
      last: "これが最後の項目です。vpn-manager.conf には説明だけが残ります。",
      removed: (alias) => `${alias} を削除しました`,
    },
    validation: {
      localName: "ローカルのホスト名には VPN 経由で接続できません",
      mdnsName: "mDNS（.local）の名前は LAN 内にしか存在せず、VPN 経由では接続できません",
      unreachableAddress: "ループバック、リンクローカル、マルチキャストのアドレスには VPN 経由で到達できません",
      alias: "エイリアスに使えるのは英小文字、数字、. _ - だけで、先頭は英字か数字にしてください",
      hostRequired: "ホストアドレスを入力してください",
      hostInvalid: "ホストアドレスはドメイン名か完全な IP アドレスにしてください（127.1 のような省略形は使えません）",
      privateAddress:
        "プライベートアドレスには、この接続のセキュリティ設定がそのネットワークを許可している場合にだけ VPN 経由で到達できます。許可されていなければゲートウェイが拒否し、通常のネットワークには切り替わりません",
      bareName: "ドメインのない名前はたいてい LAN 内でしか名前解決できず、VPN 経由では見つかりません",
      user: "ユーザー名に使えるのは英字、数字、. _ - @ だけです",
      identityFile: "~/ または / で始まり、空白、引用符、%、.. を含まないようにしてください",
      identitiesOnly: "先に鍵ファイルを指定してください",
      aliasResolvable:
        "エイリアス自体が名前解決できる場合、Include が効かなくなると ssh は直接接続します。. を含まないエイリアスをおすすめします",
      gatewayRequired: "既存のホストの項目は VPN 経由にするためのものです。ゲートウェイを選択してください",
      intervalRequired: "VPN 経由ではキープアライブ間隔（10–240 秒）が必要です",
      intervalViaVpn: "VPN 経由では 10 秒から 240 秒の間にしてください",
      intervalDirect: "10–3600 秒",
    },
  },
});
