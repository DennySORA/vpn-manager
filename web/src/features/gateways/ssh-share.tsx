// The SSH parts of a live rate, apart from each other: SSH sessions through the proxy ports (「SSH 代理」: `vpnctl
// ssh-proxy`, and any TCP connection to port 22) and VPN Manager's own SSH downloads (「SSH 下載」). Already inside the
// rate they sit under; only these class sums are measured, nothing per destination.

import { Tip } from "@/components/ui/tooltip";
import { formatBps } from "@/lib/format";
import { m } from "./messages";
import { type Flow, flowing, type PortKinds, SSH_PROXY_COLOR, SSH_PULL_COLOR } from "./ssh-traffic";

function Part({ label, color, flow, hint }: { label: string; color: string; flow: Flow; hint: string }) {
  return (
    <Tip content={hint}>
      <p
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a tooltip trigger: keyboard users focus it to read the tooltip
        tabIndex={0}
        className="flex cursor-help items-start gap-1.5 font-sans text-caption text-fg-tertiary underline decoration-dotted underline-offset-4"
      >
        <span aria-hidden className="swatch mt-1.5 size-1.5 shrink-0 rounded-full" style={{ background: color }} />
        <span>
          {m.share.part(label)} <span className="machine whitespace-nowrap">↓ {formatBps(flow.rx)}</span>{" "}
          <span className="machine whitespace-nowrap">↑ {formatBps(flow.tx)}</span>
        </span>
        <span className="sr-only">{m.share.forReader(hint)}</span>
      </p>
    </Tip>
  );
}

/** 「其中 SSH 代理 ↓x ↑y」 and 「其中 SSH 下載 ↓x ↑y」, each only when it carried traffic. `scope` says through what. */
export function SshShare({ kinds, scope }: { kinds: PortKinds; scope: "gateway" | "instance" }) {
  if (!(flowing(kinds.proxy) || kinds.sessions || flowing(kinds.pull))) return null;
  return (
    <div className="grid grid-cols-1 gap-1">
      {flowing(kinds.proxy) || kinds.sessions ? (
        <Part
          label={m.share.proxy}
          color={SSH_PROXY_COLOR}
          flow={kinds.proxy}
          hint={m.share.proxyHint(scope, kinds.sessions)}
        />
      ) : null}
      {flowing(kinds.pull) ? (
        <Part label={m.share.pull} color={SSH_PULL_COLOR} flow={kinds.pull} hint={m.share.pullHint(scope)} />
      ) : null}
    </div>
  );
}
