// Text of the chart cards of 數據統計 (../charts.tsx): each chart's title, what it plots, its series and the details
// at the cursor. The names of a connection's traffic parts, the gap reasons and the value wording are in the page's
// table (../messages.tsx); 下載, 上傳 and 未知 are the shared words (components/ui/messages.ts, `common`).

import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    traffic: {
      title: "Traffic",
      subtitle:
        "Data applications send and receive through Gateways (without the SOCKS/HTTP handshake), port forwards and the strictly isolated app sandbox, in bit/s",
      gatewaySubtitle:
        "Data applications send and receive through this Gateway (without the SOCKS/HTTP handshake), in bit/s",
      /** Before a part's two rates at the cursor: "Of which SSH proxy ↓ 1 Mbps ↑ 2 Mbps". */
      part: (label: string) => `Of which ${label}`,
    },
    wireguard: {
      subtitle:
        "Encrypted UDP datagrams (without the outer IP/UDP headers), in bit/s; they cannot be added to the traffic",
      received: "Received",
      sent: "Sent",
    },
    flows: {
      title: "Connection count",
      subtitle:
        "TCP connections and UDP flows open at once inside the tunnel, DNS and management connections included (time-weighted average)",
      gatewaySubtitle: "TCP connections and UDP associations this Gateway serves at once (time-weighted average)",
    },
    latency: {
      title: "Latency",
      subtitle:
        "Time to connect through the proxy (resolving plus connecting) and for DNS upstreams to answer; log scale, each value the upper bound of its bucket",
      gatewaySubtitle:
        "Time to connect through this Gateway (resolving plus connecting); log scale, each value the upper bound of its bucket",
      /** A connect latency series by its percentile ("p50"). */
      connect: (percentile: string) => `Connect ${percentile}`,
      noUpstream: "No queries went upstream",
      /** The connects of the window at the cursor; `notFound` follows the failures. */
      connects: (done: string, timeouts: string, failures: string, notFound: string, refused: string) =>
        `Completed ${done} · timed out ${timeouts} · failed ${failures}${notFound} · refused ${refused}`,
      dnsUpstream: (count: string, timeouts: string) => `DNS upstream ${count} · timed out ${timeouts}`,
    },
    dns: {
      title: "DNS: queries",
      subtitle: "Queries and failures through the tunnel per second (health probes excluded)",
      queries: "Queries",
      failures: "Failures",
    },
    cache: {
      title: "DNS: cache hit rate",
      subtitle: "The share of queries answered entirely from the cache",
      hitRate: "Hit rate",
      noQueries: "No queries",
    },
    cpu: {
      title: "Resources: CPU",
      subtitle: "The worker process; 100% is one logical core",
    },
    memory: {
      title: "Resources: memory",
      subtitle: "Resident memory (RSS) of the worker process; for all connections, the sum over the processes",
    },
    /** The gap reasons at the cursor. */
    gapNote: (labels: readonly string[]) => `Gaps: ${labels.join(", ")}`,
    /** A chart's accessible name. */
    chartLabel: (title: string, subtitle: string) =>
      `${title} (${subtitle}); use the left and right arrow keys to step through the values, or open the table`,
  },
  "zh-TW": {
    traffic: {
      title: "流量",
      subtitle: "應用程式經代理埠（不含 SOCKS／HTTP 握手）、轉發與嚴格隔離的 App 沙箱收發的資料，bit/s",
      gatewaySubtitle: "應用程式經這個代理埠收發的資料（不含 SOCKS／HTTP 握手），bit/s",
      part: (label) => `其中 ${label}`,
    },
    wireguard: {
      subtitle: "加密的 UDP 資料包（不含外層 IP／UDP 標頭），bit/s；與流量不能相加",
      received: "接收",
      sent: "傳送",
    },
    flows: {
      title: "連線數",
      subtitle: "tunnel 內同時開啟的 TCP 連線與 UDP 流，含 DNS 與管理用連線（時間加權平均）",
      gatewaySubtitle: "這個代理埠同時服務的 TCP 連線與 UDP 關聯（時間加權平均）",
    },
    latency: {
      title: "延遲",
      subtitle: "代理連線（解析＋連線）與 DNS 上游回答的時間；對數刻度，值為所在區間的上界",
      gatewaySubtitle: "這個代理埠的連線時間（解析＋連線）；對數刻度，值為所在區間的上界",
      connect: (percentile) => `連線 ${percentile}`,
      noUpstream: "沒有經上游的查詢",
      connects: (done, timeouts, failures, notFound, refused) =>
        `完成 ${done} 次 · 逾時 ${timeouts} · 失敗 ${failures}${notFound} · 拒絕 ${refused}`,
      dnsUpstream: (count, timeouts) => `DNS 上游 ${count} 次 · 逾時 ${timeouts}`,
    },
    dns: {
      title: "DNS：查詢",
      subtitle: "每秒經 tunnel 的查詢與失敗（不含健康探測）",
      queries: "查詢",
      failures: "失敗",
    },
    cache: {
      title: "DNS：快取命中率",
      subtitle: "完全由快取回答的查詢比例",
      hitRate: "命中率",
      noQueries: "沒有查詢",
    },
    cpu: {
      title: "資源：CPU",
      subtitle: "worker 程序；100% 等於一個邏輯核心",
    },
    memory: {
      title: "資源：記憶體",
      subtitle: "worker 程序的常駐記憶體（RSS）；全部連線時為各程序相加",
    },
    gapNote: (labels) => `缺口：${labels.join("、")}`,
    chartLabel: (title, subtitle) => `${title}（${subtitle}）；用左右鍵逐點查看數值，或開啟表格`,
  },
  ja: {
    traffic: {
      title: "トラフィック",
      subtitle:
        "アプリケーションがゲートウェイ（SOCKS／HTTP のハンドシェイクを除く）、ポート転送、厳格な分離のアプリのサンドボックスを経由して送受信したデータ、bit/s",
      gatewaySubtitle:
        "アプリケーションがこのゲートウェイ経由で送受信したデータ（SOCKS／HTTP のハンドシェイクを除く）、bit/s",
      part: (label) => `うち ${label}`,
    },
    wireguard: {
      subtitle: "暗号化された UDP データグラム（外側の IP／UDP ヘッダーを除く）、bit/s。トラフィックとは合算できません",
      received: "受信",
      sent: "送信",
    },
    flows: {
      title: "接続数",
      subtitle: "トンネル内で同時に開いている TCP 接続と UDP フロー。DNS と管理用の接続を含みます（時間加重平均）",
      gatewaySubtitle: "このゲートウェイが同時に扱っている TCP 接続と UDP アソシエーション（時間加重平均）",
    },
    latency: {
      title: "遅延",
      subtitle: "プロキシ接続（名前解決＋接続）と DNS の上流が応答するまでの時間。対数目盛りで、値はその区間の上限です",
      gatewaySubtitle: "このゲートウェイの接続時間（名前解決＋接続）。対数目盛りで、値はその区間の上限です",
      connect: (percentile) => `接続 ${percentile}`,
      noUpstream: "上流へのクエリなし",
      connects: (done, timeouts, failures, notFound, refused) =>
        `完了 ${done} 回 · タイムアウト ${timeouts} · 失敗 ${failures}${notFound} · 拒否 ${refused}`,
      dnsUpstream: (count, timeouts) => `DNS 上流 ${count} 回 · タイムアウト ${timeouts}`,
    },
    dns: {
      title: "DNS：クエリ",
      subtitle: "トンネル経由のクエリと失敗の毎秒の数（ヘルスチェックを除く）",
      queries: "クエリ",
      failures: "失敗",
    },
    cache: {
      title: "DNS：キャッシュヒット率",
      subtitle: "キャッシュだけで応答したクエリの割合",
      hitRate: "ヒット率",
      noQueries: "クエリなし",
    },
    cpu: {
      title: "リソース：CPU",
      subtitle: "worker プロセス。100% が論理コア 1 つ分です",
    },
    memory: {
      title: "リソース：メモリ",
      subtitle: "worker プロセスの常駐メモリ（RSS）。すべての接続では各プロセスの合計です",
    },
    gapNote: (labels) => `欠損：${labels.join("、")}`,
    chartLabel: (title, subtitle) =>
      `${title}（${subtitle}）。左右の矢印キーで値を 1 点ずつ確認するか、表を開いてください`,
  },
});
