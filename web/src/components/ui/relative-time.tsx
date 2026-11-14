import { relativeTime } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";

/**
 * "12 秒前": the one-second clock lives here, so a list row (or a page) showing a relative time does not re-render
 * every second — only this text does.
 */
export function RelativeTime({ at }: { at: string | null | undefined }) {
  const now = useServerNow();
  return <>{relativeTime(at, now)}</>;
}
