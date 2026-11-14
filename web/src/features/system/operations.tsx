// 操作紀錄: what this installation was asked to do and how each request ended, newest first (the list that was the top
// bar's 最近操作 drawer). It reads while the tab is open, every 5 seconds; a result that is unknown says what to do.
import { History } from "lucide-react";
import { OperationsList } from "./operations-list";
import { STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { Panel } from "@/components/ui/panel";
import { m } from "./operations/messages";

export function OperationsView() {
  return (
    <div className="space-y-4 px-4 pt-5 pb-8 md:px-6">
      <Panel
        icon={History}
        title={m.title}
        description={m.description}
        flush
        style={staggerStyle(0)}
        className={STAGGER_IN}
      >
        <OperationsList enabled />
      </Panel>
    </div>
  );
}
