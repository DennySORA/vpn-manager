// Persisted series on a time axis (數據統計, 效能統計). One y-axis per chart; each point stands for its window and is
// drawn at the window's middle. Lines connect neighbouring windows only: a null window breaks the line (an isolated
// value is a dot), so nothing is drawn across time without data. Gap bands shade the spans the API explains, restart
// markers show new generations.
//
// Callers pass stable inputs (memoized series, module-level scales and formatters): the plot layer is then recomputed
// only when the data or the size changes, never when the cursor moves. Motion (docs/frontend-design.md §8.1): the plot
// never animates — a refresh redraws in place, so nothing replays; the cursor's readout pops in on the popover glass
// when it appears (snappy), and moves with the cursor without easing (a cursor is linear). With the keyboard
// (←／→／Home／End, Escape) the readout is also announced, politely, while the chart has focus.

import {
  type KeyboardEvent,
  memo,
  type PointerEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { m as ui } from "@/components/ui/messages";
import { cn } from "@/lib/cn";
import { m } from "./messages";

export interface ChartSeries {
  key: string;
  label: string;
  /** CSS color of the marks (a series token). */
  color: string;
  values: (number | null)[];
  /** A part of another series drawn dashed (SVG dash array), so both show where they coincide. */
  dash?: string | undefined;
}

/** The background of a series' key: its colour, broken like its line when the line is dashed. */
export function swatchFill(s: Pick<ChartSeries, "color" | "dash">): string {
  return s.dash ? `repeating-linear-gradient(90deg, ${s.color} 0 3px, transparent 3px 5px)` : s.color;
}

/** A shaded span: nothing recorded (`absent`), data lost or rates undefined (`incomplete`). */
export interface Band {
  from: number;
  to: number;
  tone: "absent" | "incomplete";
}

/**
 * A y-axis. `linear` grows from 0 to a round top (at least `minTop`); `binary` rounds in the
 * binary unit the values are shown in (KiB, MiB, GiB), so gridlines read as round byte sizes.
 */
export type Scale =
  { kind: "linear"; minTop: number; binary?: boolean } | { kind: "fixed"; max: number } | { kind: "log" };

/**
 * The shared time cursor: the start of the window under it (so a refresh that slides the range
 * keeps it on the same time), and which chart the pointer or focus is on.
 */
export interface Hover {
  t: number;
  source: string;
}

/** The index of the window starting at `t`, if the frame has it. */
export function windowIndex(frame: Frame, t: number): number | null {
  const first = frame.timestamps[0];
  if (first === undefined) return null;
  const i = Math.round((t - first) / frame.stepMs);
  return frame.timestamps[i] === t ? i : null;
}

/** The windows of a series answer: their starts (ms, ascending), length and the range. */
export interface Frame {
  timestamps: number[];
  stepMs: number;
  from: number;
  to: number;
}

export interface SeriesChartProps {
  id: string;
  /** Accessible name. */
  label: string;
  frame: Frame;
  series: ChartSeries[];
  scale: Scale;
  /** Value text (tooltip). */
  format: (v: number) => string;
  /** Axis text (shorter units welcome). */
  formatAxis: (v: number) => string;
  bands: Band[];
  /** Times a new worker generation started. */
  markers: number[];
  ticks: { t: number; label: string }[];
  hover: Hover | null;
  onHover: (h: Hover | null) => void;
  /** The tooltip's heading for window `i`. */
  windowLabel: (i: number) => string;
  /** Text for a series without a value at `i` (default「未知」). */
  unknownText?: ((i: number, s: ChartSeries) => string) | undefined;
  /** Extra tooltip lines for window `i` (counts, gap reasons), or null. */
  details?: ((i: number) => ReactNode) | undefined;
  emptyText: string;
  height?: number | undefined;
}

const PAD_T = 10;
const PAD_B = 20;
/** Left gutter for the y-axis labels (up to「12.5 Mbps」in 11 px mono): they never sit on the data. */
const PAD_L = 68;
/** The readout beside the cursor (px) and its gap from the cursor. */
const TIP_W = 216;
const TIP_GAP = 12;

/** Axis text: recessive ink; the system text colour under forced colours (SVG keeps authored fills otherwise). */
const AXIS_TEXT = "fill-fg-tertiary font-mono text-micro forced-colors:fill-[CanvasText]";

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

/**
 * A round top for a linear axis (1, 1.2, 1.5, 2, 3, 4, 5, 6, 8 × 10ⁿ), at least `minTop`. The
 * middle gridline is half of it; 2.5 is left out because its half (1.25) loses a digit in a
 * one-decimal label such as「1.3 Mbps」.
 */
export function niceTop(v: number, minTop: number): number {
  if (!(v > minTop)) return minTop;
  const base = 10 ** Math.floor(Math.log10(v));
  for (const k of [1, 1.2, 1.5, 2, 3, 4, 5, 6, 8]) if (v <= k * base) return k * base;
  return 10 * base;
}

/** [`niceTop`] for byte sizes: round in the binary unit the top is shown in. */
export function niceTopBinary(v: number, minTop: number): number {
  let unit = 1;
  while (Math.max(v, minTop) / unit >= 1_024) unit *= 1_024;
  const top = niceTop(v / unit, minTop / unit) * unit;
  // 1,000–1,023 of a unit round past it: say it in the next one instead.
  return top / unit >= 1_024 ? niceTop(v / (unit * 1_024), minTop / (unit * 1_024)) * unit * 1_024 : top;
}

/** Decades around the values of a log axis: [10^⌊log v_min⌋, 10^⌈log v_max⌉], at least one decade. */
export function logDomain(values: number[]): [number, number] {
  const positive = values.filter((v) => v > 0);
  if (!positive.length) return [100, 1_000];
  const lo = 10 ** Math.floor(Math.log10(Math.min(...positive)));
  let hi = 10 ** Math.ceil(Math.log10(Math.max(...positive)));
  if (hi <= lo) hi = lo * 10;
  return [lo, hi];
}

/** Runs of consecutive known values as [first, last] index pairs. */
export function runs(values: (number | null)[]): [number, number][] {
  const out: [number, number][] = [];
  let start = -1;
  values.forEach((v, i) => {
    if (v !== null && start < 0) start = i;
    if (v === null && start >= 0) {
      out.push([start, i - 1]);
      start = -1;
    }
  });
  if (start >= 0) out.push([start, values.length - 1]);
  return out;
}

/** Where the readout goes: beside the cursor, flipped to its left near the right edge, never past the left edge. */
export function readoutLeft(cursorX: number, width: number): number {
  return cursorX + TIP_GAP + TIP_W <= width ? cursorX + TIP_GAP : Math.max(0, cursorX - TIP_GAP - TIP_W);
}

interface Geometry {
  x: (t: number) => number;
  px: (i: number) => number;
  y: (v: number) => number;
  grid: number[];
}

function geometry(frame: Frame, series: ChartSeries[], scale: Scale, width: number, height: number): Geometry {
  const plotH = height - PAD_T - PAD_B;
  const span = Math.max(1, frame.to - frame.from);
  const x = (t: number) => PAD_L + ((t - frame.from) / span) * Math.max(0, width - PAD_L);
  const px = (i: number) => {
    const start = frame.timestamps[i] ?? frame.from;
    return x((start + Math.min(start + frame.stepMs, frame.to)) / 2);
  };
  const values = series.flatMap((s) => s.values.filter((v): v is number => v !== null));
  if (scale.kind === "log") {
    const [lo, hi] = logDomain(values);
    const l0 = Math.log10(lo);
    const l1 = Math.log10(hi);
    const y = (v: number) => PAD_T + plotH - ((Math.log10(Math.max(v, lo)) - l0) / (l1 - l0)) * plotH;
    const grid: number[] = [];
    for (let d = lo; d <= hi * 1.0001; d *= 10) grid.push(d);
    return { x, px, y, grid };
  }
  const max = values.reduce((peak, v) => Math.max(peak, v), 0);
  const top = scale.kind === "fixed" ? scale.max : (scale.binary ? niceTopBinary : niceTop)(max, scale.minTop);
  const y = (v: number) => PAD_T + plotH - (Math.min(Math.max(v, 0), top) / top) * plotH;
  return { x, px, y, grid: [0, top / 2, top] };
}

interface PlotProps {
  g: Geometry;
  series: ChartSeries[];
  /** One series on a linear (open-ended) axis gets a light wash under its line. */
  wash: boolean;
  bands: Band[];
  markers: number[];
  ticks: { t: number; label: string }[];
  formatAxis: (v: number) => string;
  width: number;
  height: number;
  clip: string;
}

/** Everything that changes with the data and size, not with the cursor. */
const Plot = memo(function Plot({
  g,
  series,
  wash,
  bands,
  markers,
  ticks,
  formatAxis,
  width,
  height,
  clip,
}: PlotProps) {
  return (
    <>
      <defs>
        <clipPath id={clip}>
          <rect x={PAD_L} y={0} width={Math.max(0, width - PAD_L)} height={height - PAD_B + 1} />
        </clipPath>
      </defs>
      {bands.map((b) => {
        const x1 = Math.max(PAD_L, g.x(b.from));
        const x2 = Math.min(width, g.x(b.to));
        if (x2 - x1 < 0.5) return null;
        return (
          <rect
            key={`${b.tone}-${b.from}`}
            data-band={b.tone}
            x={x1}
            y={PAD_T}
            width={x2 - x1}
            height={height - PAD_T - PAD_B}
            // Nothing recorded: a faint neutral wash; lost or undefined: a faint warning wash (both explained in the legend).
            className={cn(
              b.tone === "incomplete" ? "fill-warning/9" : "fill-white/4",
              "forced-colors:fill-[CanvasText] forced-colors:opacity-15",
            )}
          />
        );
      })}
      {g.grid.map((v, i) => (
        <g key={v}>
          <line
            x1={PAD_L}
            x2={width}
            y1={g.y(v)}
            y2={g.y(v)}
            stroke={i === 0 ? "var(--color-line)" : "var(--color-line-subtle)"}
            strokeWidth={1}
            // Recessive under forced colours too: the text colour, faint.
            className="forced-colors:stroke-[CanvasText] forced-colors:opacity-35"
          />
          <text x={PAD_L - 6} y={g.y(v)} dy="0.32em" textAnchor="end" className={AXIS_TEXT}>
            {formatAxis(v)}
          </text>
        </g>
      ))}
      {markers.map((t) => {
        const mx = g.x(t);
        if (mx < PAD_L || mx > width) return null;
        return (
          <line
            key={t}
            data-restart
            x1={mx}
            x2={mx}
            y1={PAD_T}
            y2={height - PAD_B}
            stroke="var(--color-info)"
            strokeOpacity={0.55}
            strokeWidth={1}
          />
        );
      })}
      <g clipPath={`url(#${clip})`}>
        {series.map((s) => {
          const path = (a: number, b: number) => {
            let d = "";
            for (let i = a; i <= b; i++)
              d += `${i === a ? "M" : "L"}${g.px(i).toFixed(1)},${g.y(s.values[i] ?? 0).toFixed(1)}`;
            return d;
          };
          return (
            <g key={s.key}>
              {runs(s.values).map(([a, b]) =>
                b > a ? (
                  <g key={a}>
                    {wash ? (
                      <path
                        d={`${path(a, b)}L${g.px(b).toFixed(1)},${g.y(0).toFixed(1)}L${g.px(a).toFixed(1)},${g.y(0).toFixed(1)}Z`}
                        fill={s.color}
                        fillOpacity={0.1}
                      />
                    ) : null}
                    <path
                      d={path(a, b)}
                      fill="none"
                      stroke={s.color}
                      strokeWidth={2}
                      strokeLinejoin="round"
                      strokeLinecap={s.dash ? "butt" : "round"}
                      strokeDasharray={s.dash}
                    />
                  </g>
                ) : (
                  <circle
                    key={a}
                    cx={g.px(a)}
                    cy={g.y(s.values[a] ?? 0)}
                    r={3.5}
                    fill={s.color}
                    stroke="var(--color-surface)"
                    strokeWidth={1.5}
                  />
                ),
              )}
            </g>
          );
        })}
      </g>
      {ticks.map((t) => {
        const tx = g.x(t.t);
        if (tx < PAD_L + 20 || tx > width - 20) return null;
        return (
          <text key={t.t} x={tx} y={height - 5} textAnchor="middle" className={AXIS_TEXT}>
            {t.label}
          </text>
        );
      })}
    </>
  );
});

export function SeriesChart(p: SeriesChartProps) {
  const { id, hover, onHover, frame, series, scale } = p;
  const height = p.height ?? 168;
  const [ref, width] = useWidth();
  /** Keyboard focus is on this chart: its readout is then also announced. */
  const [focused, setFocused] = useState(false);
  const g = useMemo(() => geometry(frame, series, scale, width, height), [frame, series, scale, width, height]);
  const n = frame.timestamps.length;
  const hasData = series.some((s) => s.values.some((v) => v !== null));
  const index = hover ? windowIndex(frame, hover.t) : null;
  const at = (i: number): Hover | null => {
    const t = frame.timestamps[i];
    return t === undefined ? null : { t, source: id };
  };
  const active = hover?.source === id && index !== null;

  const pick = (e: PointerEvent<SVGSVGElement>) => {
    if (!n || width <= 0) return;
    const r = e.currentTarget.getBoundingClientRect();
    const t = frame.from + ((e.clientX - r.left - PAD_L) / Math.max(1, r.width - PAD_L)) * (frame.to - frame.from);
    const first = frame.timestamps[0] ?? frame.from;
    const i = Math.max(0, Math.min(n - 1, Math.floor((t - first) / frame.stepMs)));
    if (index !== i || hover?.source !== id) onHover(at(i));
  };
  const keys = (e: KeyboardEvent<SVGSVGElement>) => {
    if (!n) return;
    const cur = index ?? n - 1;
    let next: number | null;
    if (e.key === "ArrowLeft") next = Math.max(0, cur - 1);
    else if (e.key === "ArrowRight") next = Math.min(n - 1, cur + 1);
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = n - 1;
    else if (e.key === "Escape") next = null;
    else return;
    e.preventDefault();
    onHover(next === null ? null : at(next));
  };

  const tipX = index !== null ? g.px(index) : 0;
  const extra = active ? p.details?.(index) : null;
  const valueText = (s: ChartSeries, i: number) => {
    const v = s.values[i];
    return v === null || v === undefined ? (p.unknownText?.(i, s) ?? ui.common.unknown) : p.format(v);
  };
  return (
    <div ref={ref} className="relative" style={{ height }}>
      {width > 0 ? (
        <svg
          width={width}
          height={height}
          role="img"
          aria-label={p.label}
          tabIndex={hasData ? 0 : -1}
          onPointerMove={pick}
          onPointerLeave={() => {
            if (hover?.source === id) onHover(null);
          }}
          onKeyDown={keys}
          onFocus={() => {
            setFocused(true);
            if (!hasData) return;
            // Focus takes the shared cursor: where it already is (another chart's), else the newest window.
            if (index === null) onHover(at(n - 1));
            else if (hover?.source !== id) onHover(at(index));
          }}
          onBlur={() => {
            setFocused(false);
            if (hover?.source === id) onHover(null);
          }}
          className="block touch-none rounded-sm focus-visible:outline-offset-4"
        >
          <Plot
            g={g}
            series={series}
            wash={series.length === 1 && scale.kind === "linear"}
            bands={p.bands}
            markers={p.markers}
            ticks={p.ticks}
            formatAxis={p.formatAxis}
            width={width}
            height={height}
            clip={`sc-${id}`}
          />
          {index !== null ? (
            <g>
              <line
                x1={tipX}
                x2={tipX}
                y1={PAD_T}
                y2={height - PAD_B}
                stroke="var(--color-line-strong)"
                strokeWidth={1}
                className="forced-colors:stroke-[Highlight]"
              />
              {series.map((s) => {
                const v = s.values[index];
                return v === null || v === undefined ? null : (
                  <circle
                    key={s.key}
                    cx={tipX}
                    cy={g.y(v)}
                    r={4}
                    fill={s.color}
                    stroke="var(--color-surface)"
                    strokeWidth={2}
                  />
                );
              })}
            </g>
          ) : null}
        </svg>
      ) : null}
      {!hasData ? (
        <div
          className="pointer-events-none absolute inset-x-0 top-0 flex items-center justify-center px-6 text-center text-data text-fg-tertiary"
          style={{ height: height - PAD_B }}
        >
          {p.emptyText}
        </div>
      ) : null}
      {active && width > 0 ? (
        <div
          aria-hidden
          data-chart-readout
          className="overlay-surface pointer-events-none absolute top-0 z-10 rounded-lg px-2.5 py-2 animate-pop-in"
          // Beside the cursor, flipping to its left near the right edge; it follows the cursor without easing.
          style={{ left: readoutLeft(tipX, width), width: TIP_W }}
        >
          <p className="machine text-micro text-fg-secondary">{p.windowLabel(index)}</p>
          <div className="mt-1 space-y-0.5">
            {series.map((s) => {
              const v = s.values[index];
              const known = v !== null && v !== undefined;
              return (
                <p key={s.key} className="flex items-center justify-between gap-3 text-caption text-fg-secondary">
                  <span className="inline-flex min-w-0 items-center gap-1.5">
                    <span className="swatch h-0.5 w-2.5 shrink-0 rounded-full" style={{ background: swatchFill(s) }} />
                    <span className="truncate">{s.label}</span>
                  </span>
                  <span
                    className={cn("machine shrink-0 [overflow-wrap:normal]", known ? "text-fg" : "text-fg-tertiary")}
                  >
                    {valueText(s, index)}
                  </span>
                </p>
              );
            })}
          </div>
          {extra ? (
            <div className="mt-1.5 border-t border-white/8 pt-1.5 text-caption text-fg-secondary">{extra}</div>
          ) : null}
        </div>
      ) : null}
      {/* What the cursor reads, for the keyboard: announced only while this chart has focus. */}
      <p aria-live="polite" className="sr-only">
        {focused && active
          ? m.readout(
              p.windowLabel(index),
              series.map((s) => ({ label: s.label, value: valueText(s, index) })),
            )
          : ""}
      </p>
    </div>
  );
}
