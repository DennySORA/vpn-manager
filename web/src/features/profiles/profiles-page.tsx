// WireGuard 設定 (/profiles): the list page recipe of docs/frontend-design.md §8.1 — page header with its one primary
// action (匯入設定); a tool strip (search, usage filter, sort, count); rows that come and go with presence and slide on
// filter, sort, import and delete, one sliding selection marker; each row has its quick action (建立連線) and the same ⋯
// menu as the inspector, all from one action model (actions.ts).
import { FileKey, FilePlus2 } from "lucide-react";
import { type ReactNode, useCallback, useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useInstances, useProfiles } from "@/api/queries";
import type { InstanceView, RuntimeProfile } from "@/api/types";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { Button } from "@/components/ui/button";
import { RowActions } from "@/components/ui/entity-actions";
import { FIT_WIDTH } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { RelativeTime } from "@/components/ui/relative-time";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolStrip } from "@/components/ui/tool-strip";
import { PROVIDER_NAME } from "@/features/providers/model";
import { intlLocale } from "@/i18n";
import { absoluteTime } from "@/lib/format";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { ProfileActionHost, useProfileActions } from "./action-host";
import { ImportDialog } from "./import-dialog";
import { m } from "./messages";
import {
  matchesProfileFilter,
  matchesProfileQuery,
  PROFILE_FILTERS,
  PROFILE_SORTS,
  type ProfileFilter,
  type ProfileSort,
  profilePlace,
  profileUsers,
  sortProfiles,
} from "./model";
import { ProfileInspector } from "./profile-inspector";

const NONE: InstanceView[] = [];

function ProfileRow({
  p,
  users,
  selected,
  index,
  exiting,
  onSelect,
}: {
  p: RuntimeProfile;
  users: InstanceView[];
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useProfileActions(p, users.length);
  const place = profilePlace(p);
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting}>
      <Td className="max-w-0">
        <Link
          to={`/profiles/${p.id}`}
          data-row-link={p.id}
          aria-current={selected ? "true" : undefined}
          title={p.name}
          className="block text-body font-medium text-fg [overflow-wrap:anywhere] lg:truncate"
        >
          {p.name}
        </Link>
        <div
          className="truncate text-caption text-fg-tertiary"
          title={[PROVIDER_NAME[p.provider], place, p.peer.endpoint].filter(Boolean).join(" · ")}
        >
          {PROVIDER_NAME[p.provider]}
          {place ? ` · ${place}` : null}
          <span className="md:hidden">
            {" · "}
            <span className="font-mono">{p.peer.endpoint}</span>
          </span>
        </div>
      </Td>
      <Td className="w-[184px] max-md:hidden">
        <span className="machine text-caption text-fg-secondary">{p.peer.endpoint}</span>
      </Td>
      <Td className="w-[112px]">
        {users.length ? (
          <span className="text-data text-fg" title={m.list(users.map((v) => v.spec.name))}>
            {m.page.connections(users.length)}
          </span>
        ) : (
          <span className="text-data text-fg-tertiary">{m.look.unused}</span>
        )}
      </Td>
      <Td align="right" className="w-[104px] max-sm:hidden">
        <span className="text-caption whitespace-nowrap text-fg-tertiary" title={absoluteTime(p.created_at)}>
          <RelativeTime at={p.created_at} />
        </span>
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={p.name} />
      </Td>
    </Tr>
  );
}

export function ProfilesPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const profiles = useProfiles();
  const instances = useInstances();
  const setQueryParams = useSetQueryParams();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const [importOpen, setImportOpen] = useQueryParam("import");
  const filter = (PROFILE_FILTERS.some((f) => f.value === state) ? state : "all") as ProfileFilter;
  const sort = (PROFILE_SORTS.some((s) => s.value === sortParam) ? sortParam : "created") as ProfileSort;

  const all = useMemo(() => profiles.data ?? [], [profiles.data]);
  const usage = useMemo(() => profileUsers(instances.data ?? []), [instances.data]);
  const usersOf = useCallback((pid: string) => usage.get(pid)?.length ?? 0, [usage]);
  const rows = useMemo(
    () =>
      sortProfiles(
        all.filter(
          (p) => matchesProfileFilter(usersOf(p.id), filter) && matchesProfileQuery(p, q ?? "", usage.get(p.id)),
        ),
        sort,
      ),
    [all, filter, q, sort, usage, usersOf],
  );
  const selected = all.find((p) => p.id === id);
  useCrumb(selected?.name);

  const search = (() => {
    const s = new URLSearchParams();
    if (q) s.set("q", q);
    if (state) s.set("state", state);
    if (sortParam) s.set("sort", sortParam);
    const t = s.toString();
    return t ? `?${t}` : "";
  })();
  const select = (next: string) => {
    void navigate(`/profiles/${next}${search}`);
  };
  // Both filters in one URL change: two query setters in a row would each start from the same URL, the second
  // putting back what the first removed.
  const clearFilters = () => {
    setQueryParams({ q: null, state: null });
  };
  const onKeyDown = useRowNavigation(
    rows.map((p) => p.id),
    id,
    select,
  );
  const importButton = (
    <Button
      variant="primary"
      icon={FilePlus2}
      onClick={() => {
        setImportOpen("1", { push: true });
      }}
    >
      {m.page.import}
    </Button>
  );

  let list: ReactNode;
  if (profiles.isPending) list = <LoadingRows label={m.page.loading} />;
  else if (profiles.isError && !profiles.data)
    list = <ErrorState error={profiles.error} onRetry={() => void profiles.refetch()} retrying={profiles.isFetching} />;
  else if (!all.length)
    list = (
      <EmptyState brand icon={FileKey} title={m.page.empty} actions={importButton}>
        {m.page.emptyBody}
      </EmptyState>
    );
  else
    list = (
      <>
        <ToolStrip label={m.page.listLabel} className="px-3 py-1.5">
          <SearchInput
            value={q ?? ""}
            onChange={(v) => {
              setQ(v || null);
            }}
            label={m.page.search}
            placeholder={m.page.searchPlaceholder}
          />
          <Segmented
            label={m.page.filterByUse}
            value={filter}
            onChange={(v) => {
              setState(v === "all" ? null : v);
            }}
            options={PROFILE_FILTERS.map((f) => ({
              ...f,
              count: all.filter((p) => matchesProfileFilter(usersOf(p.id), f.value)).length,
            }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={PROFILE_SORTS}
            onChange={(v) => {
              setSort(v === "created" ? null : v);
            }}
          />
          <Count shown={rows.length} total={all.length} unit={m.unit(all.length)} />
        </ToolStrip>
        {profiles.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={profiles.error}
              title={m.page.stale(new Date(profiles.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void profiles.refetch()}
              retrying={profiles.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame label={m.title} onKeyDown={onKeyDown} selectionMarker tableClassName="max-sm:min-w-0">
            <thead>
              <tr>
                <Th>{ui.common.name}</Th>
                <Th className="max-md:hidden">{m.endpoint}</Th>
                <Th>{m.filter.used}</Th>
                <Th align="right" className="max-sm:hidden">
                  {m.created}
                </Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(p) => p.id}>
              {(p, row) => (
                <ProfileRow
                  p={p}
                  users={usage.get(p.id) ?? NONE}
                  index={row.index}
                  exiting={row.exiting}
                  selected={p.id === id}
                  onSelect={() => {
                    select(p.id);
                  }}
                />
              )}
            </TBody>
          </TableFrame>
        ) : (
          <EmptyState
            compact
            icon={FileKey}
            title={m.page.noMatch}
            actions={
              <Button size="sm" onClick={clearFilters}>
                {ui.common.clearFilters}
              </Button>
            }
          />
        )}
      </>
    );

  return (
    <Page>
      <ProfileActionHost profiles={all} usersOf={usersOf}>
        <PageHeader
          title={m.title}
          description={m.description}
          help={m.help}
          helpText={m.helpText}
          actions={importButton}
        />
        <SplitView
          list={list}
          inspector={
            selected ? (
              <ProfileInspector key={selected.id} profile={selected} users={usage.get(selected.id) ?? NONE} />
            ) : null
          }
          inspectorTitle={selected ? m.page.detailsOf(selected.name) : m.page.details}
          onCloseInspector={() => void navigate(`/profiles${search}`)}
          placeholder={
            <EmptyState compact icon={FileKey} title={id && profiles.isSuccess ? m.page.notFound : m.page.choose}>
              {id && profiles.isSuccess ? ui.common.mayHaveBeenDeleted : m.page.chooseHint}
            </EmptyState>
          }
        />
        <ImportDialog
          open={importOpen === "1"}
          onOpenChange={(o) => {
            setImportOpen(o ? "1" : null);
          }}
        />
      </ProfileActionHost>
    </Page>
  );
}
