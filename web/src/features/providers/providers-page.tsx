// 供應商 (/providers, /providers/:id): the page header with its one primary action (加入帳號); the Provider egress
// card (where every provider request leaves, and the one fix its state calls for); then the accounts (a short list)
// beside the selected account's page (MasterDetail). Each account row has its quick action (重新讀取帳號) and the same ⋯
// menu as the account page, from one action model (actions.ts); one selection marker slides between the rows.
import { Building2, Plus } from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import { Link, Navigate, useParams, useSearchParams } from "react-router";
import { useInstances, useProfiles, useProviderAccounts, useProviderEgress } from "@/api/queries";
import type { ProviderAccount } from "@/api/types";
import { useCrumb } from "@/components/shell/nav";
import { MasterDetail, Page, PageHeader } from "@/components/shell/page";
import { ActiveIndicator } from "@/components/ui/active-indicator";
import { Button } from "@/components/ui/button";
import { RowActions } from "@/components/ui/entity-actions";
import { LIST_ROW_IDLE, ROW_SELECTED, STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { PresenceList } from "@/components/ui/presence-list";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TEXT_TONE } from "@/components/ui/tones";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { AccountDialog } from "./account-dialog";
import { AccountPage } from "./account-page";
import { AccountActionHost, useAccountActions } from "./action-host";
import { EgressStrip } from "./egress";
import { m } from "./messages";
import { expiryShort, PROVIDER_NAME } from "./model";

/** One account in the list: its name, provider and paid-until state; the quick action and ⋯ beside it. */
function AccountRow({ a, selected, search }: { a: ProviderAccount; selected: boolean; search: string }) {
  const actions = useAccountActions(a);
  // Days left change once a day: read the clock when the row renders (no per-second ticking for a short list).
  const exp = expiryShort(a);
  return (
    <div
      data-selected={selected || undefined}
      className={cn(
        "relative flex min-w-0 items-center gap-1 rounded-lg pr-1.5 transition-colors duration-(--duration-fast) ease-standard",
        selected ? ROW_SELECTED : LIST_ROW_IDLE,
      )}
    >
      <Link
        to={`/providers/${a.id}${search}`}
        aria-current={selected ? "page" : undefined}
        className="block min-w-0 flex-1 rounded-lg px-3 py-2.5 no-underline outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-inset"
      >
        <span className="block text-data font-medium text-fg [overflow-wrap:anywhere]">{a.label}</span>
        <span className="block text-caption text-fg-tertiary">
          {PROVIDER_NAME[a.provider]} ·{" "}
          <span className={exp.tone === "neutral" ? undefined : TEXT_TONE[exp.tone]}>{exp.text}</span>
        </span>
      </Link>
      <RowActions actions={actions} name={a.label} />
    </div>
  );
}

function AccountList({
  accounts,
  selected,
  search,
}: {
  accounts: readonly ProviderAccount[];
  selected: string | undefined;
  search: string;
}) {
  const nav = useRef<HTMLElement>(null);
  return (
    <nav ref={nav} aria-label={m.page.accounts} className="relative min-h-0 flex-1 overflow-y-auto p-2">
      <PresenceList items={accounts} keyOf={(a) => a.id} className="grid grid-cols-1 gap-0.5">
        {(a) => <AccountRow a={a} selected={a.id === selected} search={search} />}
      </PresenceList>
      {/* One marker that slides between the rows (snappy); placed without motion the first time. */}
      <ActiveIndicator
        container={nav}
        edge="left"
        selector='[aria-current="page"]'
        inset={6}
        className="left-2 w-[3px]"
      />
    </nav>
  );
}

export function ProvidersPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const accounts = useProviderAccounts();
  const egress = useProviderEgress();
  const instances = useInstances();
  const profiles = useProfiles();
  const [adding, setAdding] = useState(params.get("add") === "1");
  // The account page's tab: another account opens on the same tab (where it has it).
  const tab = params.get("tab");
  const search = tab ? `?tab=${encodeURIComponent(tab)}` : "";
  const all = useMemo(() => accounts.data ?? [], [accounts.data]);
  const selected = id ? all.find((a) => a.id === id) : undefined;
  useCrumb(selected?.label ?? null);
  // Usable: an egress Instance is ready, or the direct bootstrap is still open (it carries
  // provider requests until the new connection takes over).
  const egressUsable = egress.data?.phase === "vpn_ready" || Boolean(egress.data?.bootstrap_expires_at);
  // The direct grant carries only building the egress (when the VPN egress itself does not work).
  const direct = egress.data?.phase === "bootstrap_direct";
  // Profiles built by each account: an account is kept while one exists.
  const built = useMemo(() => {
    const counts = new Map<string, number>();
    for (const p of profiles.data ?? [])
      if (p.source.kind === "provider") counts.set(p.source.account_id, (counts.get(p.source.account_id) ?? 0) + 1);
    return counts;
  }, [profiles.data]);
  const profilesOf = useCallback((account: string) => built.get(account) ?? 0, [built]);

  const openAdd = (o: boolean) => {
    setAdding(o);
    if (!o && params.get("add")) {
      params.delete("add");
      setParams(params, { replace: true });
    }
  };
  const addButton = (
    <Button
      variant="primary"
      icon={Plus}
      onClick={() => {
        openAdd(true);
      }}
    >
      {m.page.addAccount}
    </Button>
  );

  let detail;
  if (accounts.isError && !accounts.data)
    detail = (
      <ErrorState error={accounts.error} onRetry={() => void accounts.refetch()} retrying={accounts.isFetching} />
    );
  else if (!accounts.data) detail = <LoadingRows rows={3} label={m.page.loadingAccounts} />;
  else if (selected)
    detail = (
      <AccountPage
        key={selected.id}
        account={selected}
        egressUsable={egressUsable}
        direct={direct}
        gates={egress.data?.gates}
      />
    );
  else if (id)
    detail = (
      <EmptyState icon={Building2} title={m.page.notFound}>
        {m.page.notFoundHint}
      </EmptyState>
    );
  // The only account opens by itself; with several the user picks one.
  else if (all.length === 1 && all[0] && !adding) detail = <Navigate replace to={`/providers/${all[0].id}${search}`} />;
  else
    detail = (
      <EmptyState
        brand={!all.length}
        icon={Building2}
        title={all.length ? m.page.chooseAccount : m.page.firstAccount}
        actions={all.length ? undefined : addButton}
      >
        {all.length ? m.page.chooseAccountHint : m.page.firstAccountHint}
      </EmptyState>
    );

  return (
    <Page>
      <AccountActionHost accounts={all} egressUsable={egressUsable} direct={direct} profilesOf={profilesOf}>
        <PageHeader
          title={m.page.title}
          description={m.page.description}
          help={m.page.help}
          helpText={m.page.helpSummary}
          actions={addButton}
        />
        {/* Below md the egress card is tall: it and the accounts scroll together; above, each panel owns its scroll. */}
        <div className="flex min-h-0 flex-1 flex-col max-md:overflow-y-auto">
          <div className="shrink-0 px-4 pb-4 md:px-6">
            {egress.data ? (
              <EgressStrip status={egress.data} hasInstances={Boolean(instances.data?.length)} index={1} />
            ) : egress.isError ? (
              <div style={staggerStyle(1)} className={cn("panel", STAGGER_IN)}>
                <ErrorState
                  compact
                  error={egress.error}
                  onRetry={() => void egress.refetch()}
                  retrying={egress.isFetching}
                  title={m.page.egressUnreadable}
                />
              </div>
            ) : (
              <div style={staggerStyle(1)} className={cn("panel", STAGGER_IN)}>
                <LoadingRows rows={1} label={m.page.loadingEgress} />
              </div>
            )}
          </div>
          {/* The accounts and the selected account's page rise in after the header and the egress card. */}
          <div
            style={staggerStyle(2)}
            className={cn("flex min-h-0 flex-1 flex-col max-md:min-h-[34rem] max-md:flex-none", STAGGER_IN)}
          >
            <MasterDetail
              listLabel={m.page.accounts}
              list={
                accounts.isPending ? (
                  <LoadingRows rows={2} label={m.page.loadingAccounts} />
                ) : all.length ? (
                  <>
                    {accounts.isError ? (
                      <div className="border-b border-line-subtle p-2">
                        <ErrorCallout
                          error={accounts.error}
                          title={m.staleSince(
                            new Date(accounts.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }),
                          )}
                          onRetry={() => void accounts.refetch()}
                          retrying={accounts.isFetching}
                        />
                      </div>
                    ) : null}
                    <AccountList accounts={all} selected={id} search={search} />
                  </>
                ) : (
                  // The account page beside it says what to do; the list only says it is empty.
                  <EmptyState compact title={m.page.noAccounts} />
                )
              }
              detail={detail}
            />
          </div>
        </div>
        <AccountDialog open={adding} onOpenChange={openAdd} />
      </AccountActionHost>
    </Page>
  );
}
