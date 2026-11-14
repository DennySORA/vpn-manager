// Live payload rates (bits per second). One y-axis; download and upload are two series of the same
// measure. A gap longer than a few samples or a new generation breaks the line — nothing is drawn
// across time we did not observe. The window slides with the clock (linear: no easing, nothing replays); the cursor's
// readout pops in on the popover glass and is announced while the chart has keyboard focus (←／→／Home／End, Escape).

import { type KeyboardEvent, type PointerEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import type { LiveRates } from "@/api/types";
import { Disclosure } from "@/components/ui/disclosure";
import { m as ui } from "@/components/ui/messages";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { formatBps } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { m } from "./messages";

const RX = "var(--color-series-rx)";
const TX = "var(--color-series-tx)";
const GAP_MS = 3500;

interface Point {
  t: number;
  rx: number;
  tx: number;
  gen: number;
}

function toPoints(samples: LiveRates[], from: number): Point[] {
  const out: Point[] = [];
  for (const s of samples) {
    const t = Date.parse(s.at);
    if (Number.isFinite(t) && t >= from) out.push({ t, rx: s.payload_rx_bps, tx: s.payload_tx_bps, gen: s.generation });
  }
  return out;
}

function runs(points: Point[]): Point[][] {
  const out: Point[][] = [];
  let cur: Point[] = [];
  for (const p of points) {
    const prev = cur[cur.length - 1];
    if (prev && (p.t - prev.t > GAP_MS || p.gen !== prev.gen)) {
      out.push(cur);
      cur = [];
    }
    cur.push(p);
  }
  if (cur.length) out.push(cur);
  return out;
}

/** A round ceiling with fine steps (so a 50.4 Mbps peak gets a 60 Mbps axis, not 100), never below 1 Mbps so an idle tunnel does not look busy. */
export function niceCeil(v: number): number {
  if (!(v > 1_000_000)) return 1_000_000;
  const base = 10 ** Math.floor(Math.log10(v));
  for (const k of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8]) if (v <= k * base) return k * base;
  return 10 * base;
}

/** The latest sample, only if it is fresh (otherwise the rate is unknown, not zero). */
export function latest(samples: LiveRates[] | undefined, now: number): LiveRates | null {
  const last = samples?.[samples.length - 1];
  if (!last) return null;
  return now - Date.parse(last.at) <= GAP_MS ? last : null;
}

function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const e = entries[0];
      if (e) setWidth(Math.floor(e.contentRect.width));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);
  return [ref, width] as const;
}

const timeFmt = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/** Axis text: recessive ink; the system text colour under forced colours (SVG keeps authored fills otherwise). */
const AXIS_TEXT = "fill-fg-tertiary font-mono text-micro forced-colors:fill-[CanvasText]";
/** Gridlines stay recessive under forced colours too: the text colour, faint. */
const AXIS_HALO = "[paint-order:stroke] stroke-surface stroke-[3px] [stroke-linejoin:round]";
const GRID_LINE = "forced-colors:stroke-[CanvasText] forced-colors:opacity-35";

function Key({ color, label, value }: { color: string; label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden className="swatch h-0.5 w-3 rounded-full" style={{ background: color }} />
      <span className="text-caption text-fg-tertiary">{label}</span>
      <span className="machine text-data text-fg">{value}</span>
    </span>
  );
}

export function RateChart({
  samples,
  windowSecs = 120,
  height = 148,
  emptyText = m.rate.empty,
}: {
  samples: LiveRates[] | undefined;
  windowSecs?: number | undefined;
  height?: number | undefined;
  emptyText?: string | undefined;
}) {
  const [ref, width] = useWidth();
  const now = useServerNow();
  const clip = `rc${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const end = now;
  const start = end - windowSecs * 1000;
  const points = useMemo(() => toPoints(samples ?? [], start - GAP_MS), [samples, start]);
  const segments = useMemo(() => runs(points), [points]);
  const [hover, setHover] = useState<number | null>(null);
  /** Keyboard focus is on the chart: the readout is then also announced. */
  const [focused, setFocused] = useState(false);
  const cur = latest(samples, now);

  const padT = 18;
  const padB = 18;
  const plotH = height - padT - padB;
  const yMax = niceCeil(points.reduce((top, p) => Math.max(top, p.rx, p.tx), 0));
  const x = (t: number) => ((t - start) / (end - start)) * width;
  const y = (v: number) => padT + plotH - (Math.min(v, yMax) / yMax) * plotH;
  const line = (run: Point[], k: "rx" | "tx") =>
    run.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p[k]).toFixed(1)}`).join("");
  const area = (run: Point[], k: "rx" | "tx") => {
    const a = run[0];
    const b = run[run.length - 1];
    if (!a || !b || run.length < 2) return "";
    return `${line(run, k)}L${x(b.t).toFixed(1)},${y(0)}L${x(a.t).toFixed(1)},${y(0)}Z`;
  };

  const visible = points.filter((p) => p.t >= start);
  const hp = hover !== null ? visible[Math.min(hover, visible.length - 1)] : undefined;

  const pick = (e: PointerEvent<SVGSVGElement>) => {
    if (!visible.length) return;
    const r = e.currentTarget.getBoundingClientRect();
    const t = start + ((e.clientX - r.left) / r.width) * (end - start);
    let best = 0;
    for (let i = 1; i < visible.length; i++) {
      const p = visible[i];
      const q = visible[best];
      if (p && q && Math.abs(p.t - t) < Math.abs(q.t - t)) best = i;
    }
    setHover(best);
  };
  const keys = (e: KeyboardEvent<SVGSVGElement>) => {
    if (!visible.length) return;
    const last = visible.length - 1;
    if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? last) - 1));
    else if (e.key === "ArrowRight") setHover((h) => Math.min(last, (h ?? last) + 1));
    else if (e.key === "Home") setHover(0);
    else if (e.key === "End") setHover(last);
    else if (e.key === "Escape") setHover(null);
    else return;
    e.preventDefault();
  };

  const peak = visible.reduce((top, p) => Math.max(top, p.rx), 0);
  const summary = visible.length
    ? m.rate.summary(windowSecs / 60, formatBps(peak), formatBps(cur?.payload_rx_bps), formatBps(cur?.payload_tx_bps))
    : emptyText;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <Key color={RX} label={ui.common.download} value={formatBps(cur?.payload_rx_bps)} />
        <Key color={TX} label={ui.common.upload} value={formatBps(cur?.payload_tx_bps)} />
      </div>
      <div ref={ref} className="relative" style={{ height }}>
        {width > 0 ? (
          <svg
            width={width}
            height={height}
            role="img"
            aria-label={summary}
            tabIndex={visible.length ? 0 : -1}
            onPointerMove={pick}
            onPointerLeave={() => {
              setHover(null);
            }}
            onKeyDown={keys}
            onFocus={() => {
              setFocused(true);
            }}
            onBlur={() => {
              setFocused(false);
              setHover(null);
            }}
            className="block touch-none rounded-sm focus-visible:outline-offset-4"
          >
            <defs>
              <clipPath id={clip}>
                <rect x={0} y={0} width={width} height={height - padB} />
              </clipPath>
              <linearGradient id={`${clip}-rx`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={RX} stopOpacity="0.2" />
                <stop offset="1" stopColor={RX} stopOpacity="0.02" />
              </linearGradient>
              <linearGradient id={`${clip}-tx`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={TX} stopOpacity="0.14" />
                <stop offset="1" stopColor={TX} stopOpacity="0.01" />
              </linearGradient>
            </defs>
            {[0, 0.5, 1].map((f) => (
              <g key={f}>
                <line
                  x1={0}
                  x2={width}
                  y1={y(yMax * f)}
                  y2={y(yMax * f)}
                  stroke="var(--color-line-subtle)"
                  strokeWidth={1}
                  className={GRID_LINE}
                />
              </g>
            ))}
            <g clipPath={`url(#${clip})`}>
              {segments.map((run) => (
                <g key={`${run[0]?.gen}-${run[0]?.t}`}>
                  <path d={area(run, "rx")} fill={`url(#${clip}-rx)`} />
                  <path d={area(run, "tx")} fill={`url(#${clip}-tx)`} />
                  <path
                    d={line(run, "tx")}
                    fill="none"
                    stroke={TX}
                    strokeWidth={2}
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                  <path
                    d={line(run, "rx")}
                    fill="none"
                    stroke={RX}
                    strokeWidth={2}
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                </g>
              ))}
            </g>
            {hp ? (
              <g>
                <line
                  x1={x(hp.t)}
                  x2={x(hp.t)}
                  y1={padT - 6}
                  y2={height - padB}
                  stroke="var(--color-line-strong)"
                  strokeWidth={1}
                  className="forced-colors:stroke-[Highlight]"
                />
                <circle cx={x(hp.t)} cy={y(hp.tx)} r={4} fill={TX} stroke="var(--color-surface)" strokeWidth={2} />
                <circle cx={x(hp.t)} cy={y(hp.rx)} r={4} fill={RX} stroke="var(--color-surface)" strokeWidth={2} />
              </g>
            ) : null}
            {/* Axis values above the series, with a halo in the panel colour so a line passing under stays readable. */}
            {[0.5, 1].map((f) => (
              <text key={f} x={0} y={y(yMax * f) - 4} className={cn(AXIS_TEXT, AXIS_HALO)}>
                {formatBps(yMax * f)}
              </text>
            ))}
            <text x={0} y={height - 4} className={AXIS_TEXT}>
              {m.rate.minutesAgo(windowSecs / 60)}
            </text>
            <text x={width} y={height - 4} textAnchor="end" className={AXIS_TEXT}>
              {m.rate.now}
            </text>
          </svg>
        ) : null}
        {!visible.length ? (
          <div className="absolute inset-0 flex items-center justify-center pb-4 text-data text-fg-tertiary">
            {emptyText}
          </div>
        ) : null}
        {hp && width > 0 ? (
          <div
            aria-hidden
            data-chart-readout
            className="overlay-surface pointer-events-none absolute top-0 w-[152px] rounded-lg px-2.5 py-2 animate-pop-in"
            // Beside the crosshair, flipping to its left near the right edge; it follows the cursor without easing.
            style={{ left: x(hp.t) + 164 <= width ? x(hp.t) + 12 : Math.max(0, x(hp.t) - 164) }}
          >
            <p className="machine text-micro text-fg-secondary">{timeFmt.format(hp.t)}</p>
            <p className="mt-1 flex items-center justify-between text-caption text-fg-secondary">
              <span className="inline-flex items-center gap-1.5">
                <span className="swatch h-0.5 w-2.5 rounded-full" style={{ background: RX }} />
                {ui.common.download}
              </span>
              <span className="machine text-fg">{formatBps(hp.rx)}</span>
            </p>
            <p className="flex items-center justify-between text-caption text-fg-secondary">
              <span className="inline-flex items-center gap-1.5">
                <span className="swatch h-0.5 w-2.5 rounded-full" style={{ background: TX }} />
                {ui.common.upload}
              </span>
              <span className="machine text-fg">{formatBps(hp.tx)}</span>
            </p>
          </div>
        ) : null}
        <p aria-live="polite" className="sr-only">
          {focused && hp ? m.rate.at(timeFmt.format(hp.t), formatBps(hp.rx), formatBps(hp.tx)) : ""}
        </p>
      </div>
      <RecentTable points={visible} />
    </div>
  );
}

/** Text view of the most recent samples (the chart is never the only way to read the values). */
function RecentTable({ points }: { points: Point[] }) {
  const rows = points.slice(-8).reverse();
  if (!rows.length) return null;
  return (
    <Disclosure summary={m.rate.recent} summaryClassName="min-h-7 text-caption text-fg-tertiary">
      <table className="w-full text-caption">
        <caption className="sr-only">{m.rate.recentCaption}</caption>
        <thead>
          <tr className="text-left text-fg-tertiary">
            <th scope="col" className="py-1 font-normal">
              {m.time}
            </th>
            <th scope="col" className="py-1 text-right font-normal">
              {ui.common.download}
            </th>
            <th scope="col" className="py-1 text-right font-normal">
              {ui.common.upload}
            </th>
          </tr>
        </thead>
        <tbody className="machine text-fg-secondary">
          {rows.map((p) => (
            <tr key={p.t} className="border-t border-line-subtle">
              <td className="py-1">{timeFmt.format(p.t)}</td>
              <td className="py-1 text-right">{formatBps(p.rx)}</td>
              <td className="py-1 text-right">{formatBps(p.tx)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Disclosure>
  );
}

/** Row-sized trend (decorative; the row states the numbers in text). */
export function Sparkline({
  samples,
  width = 92,
  height = 26,
  windowSecs = 60,
  className,
}: {
  samples: LiveRates[] | undefined;
  width?: number | undefined;
  height?: number | undefined;
  windowSecs?: number | undefined;
  className?: string | undefined;
}) {
  const now = useServerNow();
  const start = now - windowSecs * 1000;
  const points = toPoints(samples ?? [], start - GAP_MS);
  const yMax = niceCeil(points.reduce((top, p) => Math.max(top, p.rx, p.tx), 0));
  const x = (t: number) => ((t - start) / (now - start)) * width;
  const y = (v: number) => height - 2 - (Math.min(v, yMax) / yMax) * (height - 4);
  const segs = runs(points);
  return (
    <svg aria-hidden width={width} height={height} className={cn("shrink-0 overflow-hidden", className)}>
      <line x1={0} x2={width} y1={height - 1.5} y2={height - 1.5} stroke="var(--color-line)" strokeWidth={1} />
      {segs.map((run) => {
        const d = (k: "rx" | "tx") =>
          run.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p[k]).toFixed(1)}`).join("");
        const a = run[0];
        const b = run[run.length - 1];
        return (
          <g key={`${a?.gen}-${a?.t}`}>
            {a && b && run.length > 1 ? (
              <path
                d={`${d("rx")}L${x(b.t).toFixed(1)},${height - 1.5}L${x(a.t).toFixed(1)},${height - 1.5}Z`}
                fill={RX}
                fillOpacity={0.12}
              />
            ) : null}
            <path d={d("tx")} fill="none" stroke={TX} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
            <path d={d("rx")} fill="none" stroke={RX} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
          </g>
        );
      })}
    </svg>
  );
}
