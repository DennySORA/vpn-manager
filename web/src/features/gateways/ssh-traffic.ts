// What proxy ports carried, by kind (bit/s): SSH sessions through them (「SSH 代理」: `vpnctl ssh-proxy`, and any TCP
// connection to port 22), VPN Manager's own SSH downloads (「SSH 下載」), and the rest — ordinary proxy traffic
// (「一般代理」). Both SSH parts are inside the ports' rates and never in each other, so the rest is what is left; a
// connection's payload also has its forwards and App sandbox, which no port carries.

import type { GatewayRates } from "@/api/types";

export interface Flow {
  rx: number;
  tx: number;
}

export interface PortKinds {
  /** SSH sessions (「SSH 代理」), and how many are open now. */
  proxy: Flow;
  sessions: number;
  /** VPN Manager's own SSH downloads (「SSH 下載」). */
  pull: Flow;
  /** Everything else the ports carried: ordinary proxy traffic. */
  other: Flow;
}

/** The kinds of what `gateways` carried, summed (a connection's: the sum over its ports). */
export function portKinds(gateways: readonly GatewayRates[]): PortKinds {
  const k: PortKinds = { proxy: { rx: 0, tx: 0 }, sessions: 0, pull: { rx: 0, tx: 0 }, other: { rx: 0, tx: 0 } };
  for (const g of gateways) {
    k.proxy.rx += g.ssh_rx_bps;
    k.proxy.tx += g.ssh_tx_bps;
    k.sessions += g.ssh_sessions;
    k.pull.rx += g.ssh_pull_rx_bps;
    k.pull.tx += g.ssh_pull_tx_bps;
    k.other.rx += Math.max(0, g.rx_bps - g.ssh_rx_bps - g.ssh_pull_rx_bps);
    k.other.tx += Math.max(0, g.tx_bps - g.ssh_tx_bps - g.ssh_pull_tx_bps);
  }
  return k;
}

/** Anything moved either way. */
export const flowing = (f: Flow) => f.rx > 0 || f.tx > 0;

/** The kinds' colours (the series tokens): their chart lines and their nodes and lanes in 流量路徑. */
export const SSH_PULL_COLOR = "var(--color-series-ssh-pull)";
export const SSH_PROXY_COLOR = "var(--color-series-ssh-proxy)";
