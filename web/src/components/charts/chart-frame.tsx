// The card around one chart (數據統計, 效能統計): its title and what it measures, the legend (two or more series; one
// series is named by the title), a 表格 toggle, and the values as a table under the chart — the chart is never the only
// way to read them. The card enters with the page (rise-in, staggered by the caller) and is never remounted by a
// refresh, so nothing replays; the table appears with a short reveal when asked for.
import { Table2 } from "lucide-react";
import { type CSSProperties, type ReactNode, useState } from "react";
import { m as ui } from "@/components/ui/messages";
import { ToolButton } from "@/components/ui/tool-strip";
import { cn } from "@/lib/cn";
import { m } from "./messages";
import { type ChartSeries, swatchFill } from "./series-chart";

/** Line keys naming each series by the colour of its line (a single series needs none: the title names it). */
export function ChartLegend({
  series,
  className,
}: {
  series: readonly Pick<ChartSeries, "key" | "label" | "color" | "dash">[];
  className?: string | undefined;
}) {
  if (series.length < 2) return null;
  return (
    <ul className={cn("flex flex-wrap items-center gap-x-3 gap-y-1", className)} aria-label={m.legend}>
      {series.map((s) => (
        <li key={s.key} className="inline-flex items-center gap-1.5 text-caption text-fg-secondary">
          <span aria-hidden className="swatch h-0.5 w-3 rounded-full" style={{ background: swatchFill(s) }} />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

/**
 * A chart's values as a table, newest first: one row per window, one column per series; a value that is not known says
 * why (never 0). `maxRows` keeps a very long range to its newest rows and says so.
 */
export function ChartTable({
  caption,
  timestamps,
  series,
  format,
  rowLabel,
  unknownText,
  maxRows,
}: {
  caption: string;
  timestamps: readonly number[];
  series: readonly ChartSeries[];
  format: (v: number) => string;
  /** The heading of the row for window `i`. */
  rowLabel: (i: number) => string;
  unknownText?: ((i: number, s: ChartSeries) => string | null) | undefined;
  maxRows?: number | undefined;
}) {
  const all = timestamps.map((t, i) => ({ t, i })).reverse();
  const rows = maxRows !== undefined ? all.slice(0, maxRows) : all;
  return (
    <div className="relative max-h-64 overflow-auto rounded-md border border-line-subtle">
      <table className="w-full border-separate border-spacing-0 text-caption">
        <caption className="sr-only">{m.tableCaption(caption)}</caption>
        <thead>
          <tr>
            <th
              scope="col"
              className="sticky top-0 z-[1] border-b border-line bg-surface px-2.5 py-1.5 text-left font-medium text-fg-tertiary"
            >
              {m.time}
            </th>
            {series.map((s) => (
              <th
                key={s.key}
                scope="col"
                className="sticky top-0 z-[1] border-b border-line bg-surface px-2.5 py-1.5 text-right font-medium text-fg-tertiary"
              >
                {s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="machine text-fg-secondary">
          {rows.map(({ t, i }) => (
            <tr key={t} className="transition-colors duration-(--duration-fast) hover:bg-raised/50">
              <th scope="row" className="border-b border-line-subtle px-2.5 py-1 text-left font-normal">
                {rowLabel(i)}
              </th>
              {series.map((s) => {
                const v = s.values[i];
                return (
                  <td key={s.key} className="border-b border-line-subtle px-2.5 py-1 text-right text-fg">
                    {v === null || v === undefined ? (
                      <span className="font-sans text-fg-tertiary">{unknownText?.(i, s) ?? ui.common.unknown}</span>
                    ) : (
                      format(v)
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length < all.length ? (
        <p className="px-2.5 py-1.5 text-micro text-fg-tertiary">{m.rowsShown(rows.length, all.length)}</p>
      ) : null}
    </div>
  );
}

/**
 * One chart card. `table` renders the values (only while shown). `compact`: a small multiple (a smaller title, no
 * panel of its own — the caller's panel frames a group of them).
 */
export function ChartFrame({
  id,
  title,
  subtitle,
  aside,
  legend,
  table,
  children,
  compact = false,
  className,
  style,
  headerClassName,
}: {
  /** Unique on the page (the heading's id). */
  id: string;
  title: string;
  subtitle?: ReactNode | undefined;
  /** Beside the title (e.g. how much of the range has values). */
  aside?: ReactNode | undefined;
  legend?: readonly Pick<ChartSeries, "key" | "label" | "color">[] | undefined;
  table: () => ReactNode;
  children: ReactNode;
  compact?: boolean | undefined;
  className?: string | undefined;
  style?: CSSProperties | undefined;
  /** Classes of the header (e.g. a minimum height so plots of one row line up). */
  headerClassName?: string | undefined;
}) {
  const [asTable, setAsTable] = useState(false);
  const titleId = `chart-${id}`;
  return (
    <section
      aria-labelledby={titleId}
      style={style}
      className={cn("flex min-w-0 flex-col gap-2.5", !compact && "panel px-4 pt-3.5 pb-3", className)}
    >
      <header className={cn("grid gap-1.5", headerClassName)}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3
              id={titleId}
              className={cn("font-semibold text-fg [overflow-wrap:anywhere]", compact ? "text-data" : "text-body")}
            >
              {title}
              {aside ? (
                <span className="ml-2 text-caption font-normal whitespace-nowrap text-fg-tertiary">{aside}</span>
              ) : null}
            </h3>
            {subtitle ? <p className="text-caption text-fg-tertiary">{subtitle}</p> : null}
          </div>
          <ToolButton
            label={m.tableOf(title)}
            aria-label={m.tableOf(title)}
            icon={<Table2 aria-hidden />}
            pressed={asTable}
            onClick={() => {
              setAsTable((v) => !v);
            }}
            className="-mr-1 text-caption"
            text={m.table}
          />
        </div>
        {legend ? <ChartLegend series={legend} /> : null}
      </header>
      {children}
      {asTable ? <div className="animate-reveal">{table()}</div> : null}
    </section>
  );
}
