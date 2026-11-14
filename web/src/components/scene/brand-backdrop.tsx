// The brand scene behind a brand moment (boot and route loading, page-level empty states, the 總覽 ambient
// background). This small module stays in the main bundle; three.js and the scene arrive lazily on first use.
// Until then (and when WebGL is unavailable, fails or loses its context) the DOM content in front keeps its own CSS
// visual (the breathing mark, the icon tile) over a soft CSS glow, so nothing ever waits for the canvas.
// Pauses while the page is hidden or the backdrop is offscreen; a falling frame rate switches to the low tier;
// a lost context shows the DOM visual and remounts the canvas once the browser restores it.
import { Component, lazy, type ReactNode, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import type { SceneTier, SceneVariant } from "./brand-scene";

const BrandScene = lazy(() => import("./brand-scene"));

let webglSupport: boolean | null = null;

/** WebGL 2 is available (checked once; the probe context is released at once). */
function hasWebgl(): boolean {
  if (webglSupport !== null) return webglSupport;
  try {
    const gl = document.createElement("canvas").getContext("webgl2");
    webglSupport = gl !== null;
    gl?.getExtension("WEBGL_lose_context")?.loseContext();
  } catch {
    webglSupport = false;
  }
  return webglSupport;
}

/** The starting tier: few cores or little memory start low (the scene can still fall to low later). */
function initialTier(): SceneTier {
  const nav = navigator as Navigator & { deviceMemory?: number };
  const cores = nav.hardwareConcurrency;
  const memory = nav.deviceMemory ?? 8;
  return cores <= 4 || memory <= 4 ? "low" : "normal";
}

/** Page visible and backdrop on screen. */
function useOnScreen(target: React.RefObject<HTMLElement | null>): boolean {
  const [visible, setVisible] = useState(true);
  const [onScreen, setOnScreen] = useState(true);
  useEffect(() => {
    const update = () => {
      setVisible(document.visibilityState === "visible");
    };
    update();
    document.addEventListener("visibilitychange", update);
    return () => {
      document.removeEventListener("visibilitychange", update);
    };
  }, []);
  useEffect(() => {
    const element = target.current;
    if (!element || typeof IntersectionObserver === "undefined") return undefined;
    const observer = new IntersectionObserver((entries) => {
      const last = entries.at(-1);
      if (last) setOnScreen(last.isIntersecting);
    });
    observer.observe(element);
    return () => {
      observer.disconnect();
    };
  }, [target]);
  return visible && onScreen;
}

/** A render or shader failure inside the scene: keep the DOM visual. */
class SceneBoundary extends Component<{ children: ReactNode; onError: () => void }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  override componentDidCatch(): void {
    this.props.onError();
  }
  override render(): ReactNode {
    return this.state.failed ? null : this.props.children;
  }
}

/** How long to wait for the browser to restore a lost context before remounting the canvas anyway. */
const RESTORE_MS = 1500;

export function BrandBackdrop({ variant, className }: { variant: SceneVariant; className?: string | undefined }) {
  const host = useRef<HTMLDivElement>(null);
  const active = useOnScreen(host);
  const [tier, setTier] = useState<SceneTier>(initialTier);
  const [failed, setFailed] = useState(false);
  const [lost, setLost] = useState(false);
  const [generation, setGeneration] = useState(0);
  const [supported] = useState(hasWebgl);

  const onDecline = useCallback(() => {
    setTier("low");
  }, []);
  const onContextLost = useCallback(() => {
    setLost(true);
  }, []);
  const onError = useCallback(() => {
    setFailed(true);
  }, []);

  // A lost context: show the DOM visual, then mount a fresh canvas (a new context) after a short wait.
  useEffect(() => {
    if (!lost) return undefined;
    const timer = window.setTimeout(() => {
      setLost(false);
      setGeneration((g) => g + 1);
    }, RESTORE_MS);
    return () => {
      window.clearTimeout(timer);
    };
  }, [lost]);

  const showScene = supported && !failed && !lost;
  return (
    <div
      ref={host}
      aria-hidden
      className={cn("brand-backdrop pointer-events-none absolute inset-0 overflow-hidden", className)}
      data-variant={variant}
    >
      {showScene && (
        <SceneBoundary key={generation} onError={onError}>
          <Suspense fallback={null}>
            <div className="brand-backdrop-canvas absolute inset-0">
              <BrandScene
                variant={variant}
                tier={tier}
                active={active}
                onDecline={onDecline}
                onContextLost={onContextLost}
              />
            </div>
          </Suspense>
        </SceneBoundary>
      )}
    </div>
  );
}
