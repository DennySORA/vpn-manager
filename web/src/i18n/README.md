# Interface languages

The web UI speaks English (`en`), Traditional Chinese (`zh-TW`) and Japanese (`ja`). `index.ts` picks the
language when the page loads (the remembered choice, else the browser's first language that is one of ours, else
English) and keeps it for the life of the page; the menu in the top bar stores another choice and reloads.

## Where text lives

- Every string a person reads — labels, titles, placeholders, tooltips, `aria-label`s, toasts, validation
  messages, document titles — is an entry of a `messages.ts` table in the same folder as the code that shows it.
  One file per folder, exported as `m`:

  ```ts
  import { defineMessages } from "@/i18n";

  export const m = defineMessages({
    en: {
      title: "Gateways",
      unit: (count: number) => (count === 1 ? "gateway" : "gateways"),
      removed: (name: string) => `“${name}” was deleted`,
    },
    "zh-TW": { title: "代理埠", unit: () => "個代理埠", removed: (name) => `已刪除「${name}」` },
    ja: { title: "ゲートウェイ", unit: () => "件のゲートウェイ", removed: (name) => `「${name}」を削除しました` },
  });
  ```

- English is the reference table: TypeScript requires the other two to have exactly its entries, of the same
  kind. Type a function's parameters in the English table only; a translation may take fewer parameters.
- ESLint (`eslint.config.ts`) refuses CJK text in any other source file under `src/`, and CJK text inside an
  English table. Tests and their fixtures (`*.test.ts(x)`, `test-fixtures.ts`, `src/test/`) are exempt: they run in
  Traditional Chinese (`src/test/setup.ts`).
- Words every screen uses (Cancel, Save, Delete, Name, Unknown …) are in `components/ui/messages.ts` under
  `common`; import it as `import { m as ui } from "@/components/ui/messages"`. The section names are in
  `components/shell/messages.ts` (`m.nav`).

## Rules

1. A sentence with a value in it is a function of that value. Never join translated fragments in a component:
   word order differs between the languages. `(name: string) => …`, not `"Deleted " + name`.
2. A count that changes the English wording (singular and plural) is a parameter of the entry.
3. A sentence that contains markup (a link, `<code>`, emphasis) is a function that takes the nodes and returns a
   `ReactNode`; name the file `messages.tsx` then.
4. Keys say what the text is for (`deleteConfirmTitle`), not what it says. Group the entries of one part of a
   screen in a nested object.
5. Not translated: product, protocol and format names (VPN Manager, WireGuard, SOCKS5, HTTP, DNS, DoT, DoH, SSH,
   SFTP, tunnel, Instance, Mixed), identifiers, units (`bps`, `MiB`, `ms`), key names, commands and paths.
6. Numbers, dates and lists go through `Intl` with `intlLocale` (`lib/format.ts` has the helpers).
7. Text the service wrote (an error's `message`, a `reason`, a diagnostic) is a `ServerText`, `{en, zh-TW, ja}`:
   show it with `localized(text)`, never the object itself (ESLint's `no-base-to-string` and
   `restrict-template-expressions` catch it in a template literal). Decide by codes (`code`, `reason_code`,
   enums), never by its words. A built-in blocklist keeps the Traditional Chinese name it was created with until
   the owner renames it: show `listName(view)` (`features/security/model.ts`), and save the stored name when the
   shown one was left as it is. Tests build server text with `serverText()` from `src/test/fixtures.ts`.
8. Style. English: sentence case, plain words, no exclamation marks; buttons are verbs (“Save”, “Delete”).
   Traditional Chinese: Taiwan usage, full-width punctuation, a space between Chinese and Latin letters or digits
   (「SSH 下載」). Japanese: です・ます体 for sentences, nouns or plain verbs for labels and buttons (「保存」「キャンセル」),
   full-width punctuation, the same space between Japanese and Latin letters or digits.

## Vocabulary

| Traditional Chinese    | English                      | Japanese                               |
| ---------------------- | ---------------------------- | -------------------------------------- |
| 連線（Instance）       | connection                   | 接続                                   |
| 出口                   | exit                         | 出口                                   |
| Provider 出口          | Provider egress              | Provider 出口                          |
| 供應商                 | provider                     | プロバイダー                           |
| 帳號                   | account                      | アカウント                             |
| 裝置                   | device                       | デバイス                               |
| WireGuard 設定         | WireGuard profile            | WireGuard 設定                         |
| 設定檔                 | configuration file           | 設定ファイル                           |
| 端點                   | endpoint                     | エンドポイント                         |
| 公開金鑰／私鑰         | public key / private key     | 公開鍵／秘密鍵                         |
| 金鑰保管庫             | key vault                    | 鍵保管庫                               |
| 代理埠                 | Gateway                      | ゲートウェイ                           |
| 受管 App               | managed app                  | 管理対象アプリ                         |
| 轉發                   | port forward                 | ポート転送                             |
| 連入                   | inbound                      | 着信                                   |
| 嚴格隔離               | strict isolation             | 厳格な分離                             |
| 沙箱                   | sandbox                      | サンドボックス                         |
| 強制代理               | enforced proxy               | 強制プロキシ                           |
| 直連                   | direct connection            | 直接接続                               |
| DNS 設定               | DNS profile                  | DNS 設定                               |
| 伺服器                 | server                       | サーバー                               |
| 解析                   | resolve                      | 名前解決                               |
| 傳輸設定               | transport profile            | トランスポート設定                     |
| 往返時間               | round-trip time              | 往復時間                               |
| 緩衝                   | buffer                       | バッファー                             |
| 壅塞控制               | congestion control           | 輻輳制御                               |
| 健康探測               | health probe                 | ヘルスチェック                         |
| 握手                   | handshake                    | ハンドシェイク                         |
| 安全設定               | security profile             | セキュリティ設定                       |
| 私網                   | private network              | プライベートネットワーク               |
| 允許／拒絕             | allow / refuse               | 許可／拒否                             |
| IP 封鎖清單            | IP blocklist                 | IP ブロックリスト                      |
| 自動封鎖               | auto-ban                     | 自動ブロック                           |
| 急停                   | emergency stop               | 緊急停止                               |
| 啟動／停止／重新啟動   | start / stop / restart       | 開始／停止／再起動                     |
| 就緒                   | ready                        | 準備完了                               |
| 代（generation）       | generation                   | 世代                                   |
| 證據                   | evidence                     | エビデンス                             |
| 需要處理               | needs attention              | 要対応                                 |
| 流量                   | traffic                      | トラフィック                           |
| 下載／上傳             | download / upload            | ダウンロード／アップロード             |
| 速率                   | rate                         | 速度                                   |
| 延遲                   | latency                      | 遅延                                   |
| 操作紀錄               | operation log                | 操作履歴                               |
| 日誌                   | log                          | ログ                                   |
| 下載工作               | download job                 | ダウンロードジョブ                     |
| 遠端資料夾／本機資料夾 | remote folder / local folder | リモートフォルダー／ローカルフォルダー |
| 核心服務（manager）    | core service                 | コアサービス                           |
| 控制器（controller）   | controller                   | コントローラー                         |
| 詳細資料               | details                      | 詳細                                   |
| 待套用                 | pending                      | 適用待ち                               |
