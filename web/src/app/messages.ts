// Text of the router: the loading screen, the error boundary and the page for an unknown path.

import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    loadingPage: "Loading the page…",
    notFound: "Page not found",
    notFoundHint: "The address may no longer be valid.",
    notFoundOrDeleted: "The address may no longer be valid, or the item has been deleted.",
    renderError: "This screen ran into an error",
    renderErrorHint: "The VPN connections are not affected; reloading usually brings it back.",
    reload: "Reload",
    backToOverview: "Back to Overview",
  },
  "zh-TW": {
    loadingPage: "正在載入頁面…",
    notFound: "找不到這個頁面",
    notFoundHint: "網址可能已失效。",
    notFoundOrDeleted: "網址可能已失效，或項目已被刪除。",
    renderError: "這個畫面發生錯誤",
    renderErrorHint: "VPN 連線不受影響；重新載入通常可以恢復。",
    reload: "重新載入",
    backToOverview: "回到總覽",
  },
  ja: {
    loadingPage: "ページを読み込んでいます…",
    notFound: "ページが見つかりません",
    notFoundHint: "アドレスが無効になっている可能性があります。",
    notFoundOrDeleted: "アドレスが無効になっているか、項目が削除された可能性があります。",
    renderError: "この画面でエラーが発生しました",
    renderErrorHint: "VPN 接続には影響しません。再読み込みするとたいてい元に戻ります。",
    reload: "再読み込み",
    backToOverview: "概要に戻る",
  },
});
