// Query keys, shared by the queries and the event stream that patches them.
export const keys = {
  system: ["system"] as const,
  capabilities: ["capabilities"] as const,
  instances: ["instances"] as const,
  profiles: ["profiles"] as const,
  gateways: ["gateways"] as const,
  /** Under `gateways`: a change to any Gateway refreshes the suggestion too. */
  freePort: (from: number) => ["gateways", "free-port", from] as const,
  dns: ["dns-profiles"] as const,
  security: ["security-profiles"] as const,
  transport: ["transport-profiles"] as const,
  /** Under `transport`: the profiles that are part of the program (they change only with it). */
  builtinTransports: ["transport-profiles", "builtin"] as const,
  secrets: ["secrets"] as const,
  settings: ["settings"] as const,
  ssh: ["ssh"] as const,
  sshHosts: ["ssh-hosts"] as const,
  providerEgress: ["provider-egress"] as const,
  providerAccounts: ["provider-accounts"] as const,
  providerDevices: (id: string) => ["provider-accounts", id, "devices"] as const,
  providerServers: (id: string) => ["provider-accounts", id, "servers"] as const,
  /** AirVPN's forwarded ports of one account (read from its website through the egress). */
  providerPorts: (id: string) => ["provider-accounts", id, "forwarded-ports"] as const,
  live: (id: string) => ["live", id] as const,
  apps: ["apps"] as const,
  /** Under `apps`: reloading the list refreshes an open App's tree and log too. */
  appProcesses: (id: string) => ["apps", id, "processes"] as const,
  appLog: (id: string) => ["apps", id, "log"] as const,
  executableCheck: (path: string) => ["executable-check", path] as const,
  forwards: ["forward-bindings"] as const,
  metricsSeries: (range: string, scope: string) => ["metrics", "series", range, scope] as const,
  metricsStatus: ["metrics", "status"] as const,
  blocklists: ["blocklists"] as const,
  /** Under `blocklists`: any list change refreshes the built-in catalogue's state too. */
  builtinBlocklists: ["blocklists", "builtin"] as const,
  /** Under `bans`: lifting one refreshes every filter. */
  bans: (instance: string | null) => ["bans", instance ?? "all"] as const,
  allBans: ["bans"] as const,
  inbound: ["security-inbound"] as const,
  operations: ["operations"] as const,
  diagnostics: ["diagnostics"] as const,
  recovery: ["recovery"] as const,
  /** Performance Manager: the passive analysis and its series. */
  perfSummary: ["performance", "summary"] as const,
  perfSeries: (scope: string, range: string) => ["performance", "series", scope, range] as const,
};
