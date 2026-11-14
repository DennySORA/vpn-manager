// Text of the components that sit directly in components/.

import { defineMessages } from "@/i18n";

export const m = defineMessages({
  en: {
    discardTitle: "Discard unsaved changes?",
    discardConfirm: "Discard and leave",
    discardBody: "This item has changes that are not saved; they are lost when you leave.",
  },
  "zh-TW": {
    discardTitle: "捨棄未儲存的變更？",
    discardConfirm: "捨棄並離開",
    discardBody: "這個項目有尚未儲存的修改，離開後會遺失。",
  },
  ja: {
    discardTitle: "保存していない変更を破棄しますか？",
    discardConfirm: "破棄して移動",
    discardBody: "この項目には保存していない変更があり、移動すると失われます。",
  },
});
