import type { AppResource } from "@/api/types";
import { m } from "./messages";
import { RUN_STATE } from "./model";

/** The managed-App process trees the manager supervises (system pages, owned resources). */
export function AppResourceList({ apps, name }: { apps: AppResource[]; name: (id: string) => string }) {
  if (!apps.length) return <span className="text-fg-tertiary">{m.resources.none}</span>;
  return (
    <ul className="grid grid-cols-1 gap-0.5">
      {apps.map((a) => (
        <li key={a.pid} className="machine">
          pid {a.pid} · <span className="font-sans">{name(a.app_id)}</span>
          <span className="ml-1.5 font-sans text-fg-tertiary">
            {m.resources.summary(RUN_STATE[a.state].label, a.process_count)}
          </span>
        </li>
      ))}
    </ul>
  );
}
