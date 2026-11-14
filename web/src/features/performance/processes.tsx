// 程序 of 效能統計: CPU and memory by role (the product total first), each process on demand. A process is its pid plus
// its start time; values that a platform does not report say why. The per-process list opens with the shared
// disclosure (chevron snappy, height smooth) and its rows come and go with presence.

import { Cpu } from "lucide-react";
import type { CSSProperties } from "react";
import type { PerformanceOverview } from "@/api/generated/PerformanceOverview";
import { Disclosure } from "@/components/ui/disclosure";
import { STAGGER_IN } from "@/components/ui/look";
import { Panel } from "@/components/ui/panel";
import { PresenceList } from "@/components/ui/presence-list";
import { TableFrame, TBody, Td, Th, Tr } from "@/components/ui/table";
import { cn } from "@/lib/cn";
import { m } from "./messages";
import { bytesObs, obs, pct, ROLE_LABEL } from "./model";
import { Val } from "./values";

export function Processes({ s, style }: { s: PerformanceOverview; style?: CSSProperties }) {
  const sys = s.system;
  const rows = [sys.product, ...sys.roles];
  return (
    <Panel
      flush
      icon={Cpu}
      title={m.processes.title}
      description={m.processes.description(sys.sample_interval_secs)}
      style={style}
      className={cn("overflow-hidden", STAGGER_IN)}
    >
      {/* On a narrow screen the whole-host share and the sampled peak give way; the rest fits without scrolling. */}
      <TableFrame label={m.processes.table} tableClassName="min-w-[640px] max-md:min-w-0">
        <thead>
          <tr>
            <Th>{m.processes.role}</Th>
            <Th align="right">{m.processes.count}</Th>
            <Th align="right">{m.cpuCore}</Th>
            <Th align="right" className="max-md:hidden">
              {m.processes.cpuHost}
            </Th>
            <Th align="right">RSS</Th>
            <Th align="right" className="max-md:hidden">
              {m.processes.peakRss}
            </Th>
          </tr>
        </thead>
        <TBody items={rows} keyOf={(r) => r.role ?? "product"}>
          {(r, row) => (
            <Tr index={row.index} exiting={row.exiting} className={r.role === null ? "bg-raised/40" : undefined}>
              <Td className={cn("text-data", r.role === null ? "font-medium text-fg" : "text-fg-secondary")}>
                {r.role === null ? m.processes.total : ROLE_LABEL[r.role]}
              </Td>
              <Td align="right" className="machine">
                {r.processes}
              </Td>
              <Td align="right">
                <Val v={obs(r.cpu_core_pct, pct)} />
              </Td>
              <Td align="right" className="max-md:hidden">
                <Val v={obs(r.cpu_host_pct, pct)} />
              </Td>
              <Td align="right" className="whitespace-nowrap">
                <Val v={bytesObs(r.rss_bytes)} />
              </Td>
              <Td align="right" className="max-md:hidden">
                <Val v={bytesObs(r.sampled_peak_rss_bytes)} />
              </Td>
            </Tr>
          )}
        </TBody>
      </TableFrame>
      <div className="border-t border-line-subtle px-4 py-1.5">
        <Disclosure
          summary={m.processes.each(sys.processes.length)}
          summaryClassName="text-caption text-action-fg hover:text-action-fg"
        >
          <PresenceList
            items={sys.processes}
            keyOf={(p) => `${p.role}-${p.process_identity}`}
            className="divide-y divide-line-subtle pb-1"
            label={m.processes.eachLabel}
          >
            {(p) => (
              <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 py-1.5">
                <span className="min-w-0 text-data text-fg-secondary">
                  {ROLE_LABEL[p.role]}
                  {p.generation !== null ? (
                    <span className="machine ml-1.5 text-caption text-fg-tertiary">{m.generation(p.generation)}</span>
                  ) : null}
                </span>
                <span className="machine text-caption text-fg-tertiary">{p.process_identity}</span>
                <span className="flex items-center gap-3 text-caption">
                  <Val v={obs(p.cpu_core_pct, pct)} />
                  <Val v={bytesObs(p.rss_bytes)} />
                  <span className="machine text-fg-tertiary">{p.fd_count ?? "—"} fd</span>
                </span>
              </div>
            )}
          </PresenceList>
        </Disclosure>
      </div>
    </Panel>
  );
}
