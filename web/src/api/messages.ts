// Text of the API client: what it says when the service gave no usable answer of its own.

import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    timeout: "The VPN Manager service took too long to answer",
    unreachable: "Cannot reach the VPN Manager service",
    requestFailed: (status: number) => `The request failed (HTTP ${status})`,
    unknownOutcome: "No answer came back: the outcome is unknown. Look the result up instead of sending it again",
    unexpected: "An unexpected error occurred",
  },
  "zh-TW": {
    timeout: "VPN Manager 服務回應逾時",
    unreachable: "無法連線到 VPN Manager 服務",
    requestFailed: (status) => `請求失敗（HTTP ${status}）`,
    unknownOutcome: "沒有收到回應：結果未知，請查詢結果而不要重送",
    unexpected: "發生未預期的錯誤",
  },
  ja: {
    timeout: "VPN Manager サービスの応答がタイムアウトしました",
    unreachable: "VPN Manager サービスに接続できません",
    requestFailed: (status) => `リクエストに失敗しました（HTTP ${status}）`,
    unknownOutcome: "応答がありません：結果は不明です。再送せずに結果を確認してください",
    unexpected: "予期しないエラーが発生しました",
  },
});
