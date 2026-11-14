// Text of the resource limits and bandwidth caps: the names of the limits, what the App form says about each one, and
// the rows that show what the OS enforces. 不限 and 沒有 are the shared words (components/ui/messages.ts, `common`).

import { defineMessages } from "@/i18n";

const listEn = new Intl.ListFormat("en", { style: "long", type: "conjunction" });

/** The space between text that ends in a Latin letter, a digit or a bracket and the Japanese text after it. */
function gapAfterLatin(text: string): string {
  return /[A-Za-z0-9)]$/.test(text) ? " " : "";
}

export const m = defineMessages({
  en: {
    capNotNumber: "Enter a number (Mbit/s); empty means unlimited",
    /** The limits by name, as the OS enforces them. */
    kind: {
      memory: "Memory",
      cpu: "CPU",
      processes: "Processes (threads included)",
      open_files: "Open files",
    },
    /** One limit in force with its value (“Memory 768 MiB”). */
    enforced: (kind: string, value: string) => `${kind} ${value}`,
    /** What one mechanism enforces (“cgroup: Memory 768 MiB, Processes 128”). */
    byMechanism: (mechanism: string, limits: readonly string[]) => `${mechanism}: ${limits.join(", ")}`,
    /** The limits an App can set: the field, the range its value must be in, and the value once it is set. */
    field: {
      memory_mib: {
        label: "Memory",
        hint: "The whole process tree; the system ends it when it goes over (swap is not used).",
        range: (min: number, max: number) => `${min}–${max} MiB`,
        set: (value: number) => `Memory ${value} MiB`,
      },
      cpu_percent: {
        label: "CPU",
        hint: "Percent of one core; 200 = two cores.",
        range: (min: number, max: number) => `${min}–${max}%`,
        set: (value: number) => `CPU ${value}%`,
      },
      processes: {
        label: "Processes",
        hint: "Processes and threads of the whole process tree, in total.",
        range: (min: number, max: number) => `${min}–${max}`,
        set: (value: number) => `Processes ${value}`,
      },
      open_files: {
        label: "Open files",
        hint: "A limit of each process on its own (sockets included).",
        range: (min: number, max: number) => `${min}–${max}`,
        set: (value: number) => `Open files ${value}`,
      },
    },
    /** The unit of a limit that is a count, shown with its field's label; English says none («Processes 128»). */
    countUnit: "",
    /** The limits an App sets, in one line. */
    setList: (limits: readonly string[]) => limits.join(", "),
    readingCapabilities: "Reading which limits this host supports…",
    notReported: "The core service did not report this limit",
    inForce: "Limits in force",
    /** What else to know about a limit in force. */
    note: (kind: string, note: string) => `${kind}: ${note}`,
    notInForce: "Not in force",
    unenforced: (kinds: readonly string[]) =>
      `${kinds.length === 1 ? "Limit" : "Limits"} not in force: ${listEn.format(kinds)}`,
    /** Why, right after the limits that are not in force (the service's words, a sentence of its own). */
    unenforcedReason: (reason: string) => `. ${reason}`,
    cgroupUsage: "cgroup usage",
    oomKills: (count: number) =>
      count === 1 ? "Ended once for exceeding the memory limit" : `Ended ${count} times for exceeding the memory limit`,
  },
  "zh-TW": {
    capNotNumber: "請輸入數字（Mbit/s），留空表示不限",
    kind: {
      memory: "記憶體",
      cpu: "CPU",
      processes: "程序（含執行緒）",
      open_files: "開啟檔案",
    },
    enforced: (kind, value) => `${kind} ${value}`,
    byMechanism: (mechanism, limits) => `${mechanism}：${limits.join("、")}`,
    field: {
      memory_mib: {
        label: "記憶體",
        hint: "整個程序樹；超過時由系統結束（不使用 swap）。",
        range: (min, max) => `${min}–${max} MiB`,
        set: (value) => `記憶體 ${value} MiB`,
      },
      cpu_percent: {
        label: "CPU",
        hint: "單一核心的百分比，200 = 兩個核心。",
        range: (min, max) => `${min}–${max} %`,
        set: (value) => `CPU ${value}%`,
      },
      processes: {
        label: "程序數",
        hint: "整個程序樹的程序與執行緒總數。",
        range: (min, max) => `${min}–${max} 個`,
        set: (value) => `程序數 ${value} 個`,
      },
      open_files: {
        label: "開啟檔案",
        hint: "每個程序各自的上限（含 socket）。",
        range: (min, max) => `${min}–${max} 個`,
        set: (value) => `開啟檔案 ${value} 個`,
      },
    },
    countUnit: "個",
    setList: (limits) => limits.join("、"),
    readingCapabilities: "正在讀取這台主機支援的上限…",
    notReported: "核心服務沒有回報這種上限",
    inForce: "生效的上限",
    note: (kind, note) => `${kind}：${note}`,
    notInForce: "未生效",
    unenforced: (kinds) => `${kinds.join("、")}上限未生效`,
    unenforcedReason: (reason) => `：${reason}`,
    cgroupUsage: "cgroup 用量",
    oomKills: (count) => `記憶體超限被結束 ${count} 次`,
  },
  ja: {
    capNotNumber: "数値を入力してください（Mbit/s）。空欄にすると無制限です",
    kind: {
      memory: "メモリ",
      cpu: "CPU",
      processes: "プロセス（スレッドを含む）",
      open_files: "開けるファイル数",
    },
    enforced: (kind, value) => `${kind} ${value}`,
    byMechanism: (mechanism, limits) => `${mechanism}：${limits.join("、")}`,
    field: {
      memory_mib: {
        label: "メモリ",
        hint: "プロセスツリー全体。超えるとシステムが終了させます（swap は使いません）。",
        range: (min, max) => `${min}–${max} MiB`,
        set: (value) => `メモリ ${value} MiB`,
      },
      cpu_percent: {
        label: "CPU",
        hint: "1 コアに対する割合。200 = 2 コア。",
        range: (min, max) => `${min}–${max}%`,
        set: (value) => `CPU ${value}%`,
      },
      processes: {
        label: "プロセス数",
        hint: "プロセスツリー全体のプロセスとスレッドの合計数。",
        range: (min, max) => `${min}–${max} 個`,
        set: (value) => `プロセス数 ${value} 個`,
      },
      open_files: {
        label: "開けるファイル数",
        hint: "プロセスごとの上限（ソケットを含む）。",
        range: (min, max) => `${min}–${max} 個`,
        set: (value) => `開けるファイル数 ${value} 個`,
      },
    },
    countUnit: "個",
    setList: (limits) => limits.join("、"),
    readingCapabilities: "このホストが対応している上限を読み込んでいます…",
    notReported: "コアサービスがこの上限を報告していません",
    inForce: "適用中の上限",
    note: (kind, note) => `${kind}：${note}`,
    notInForce: "未適用",
    unenforced: (kinds) => {
      const list = kinds.join("、");
      return `${list}${gapAfterLatin(list)}の上限は適用されていません`;
    },
    unenforcedReason: (reason) => `：${reason}`,
    cgroupUsage: "cgroup 使用量",
    oomKills: (count) => `メモリ上限の超過により ${count} 回終了`,
  },
});
