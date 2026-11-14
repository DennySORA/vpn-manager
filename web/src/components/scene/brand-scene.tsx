// The brand scene (three.js through React Three Fiber): a drifting field of signal light with a few tunnels of light
// flowing across it, cyan → blue → iris → violet. Brand moments only (boot and route loading, page-level empty states,
// the 總覽 ambient background); never behind tables, forms, inspectors, settings, logs or charts.
// This module is loaded lazily by `brand-backdrop.tsx`, so screens without a scene never download three.js.
//
// One draw call: every point is placed on the GPU from its seed and the elapsed time, so no buffer is uploaded per
// frame. One frame-loop owner (R3F); time advances by a clamped delta, so a pause (hidden page, offscreen canvas) never
// replays a backlog. Geometry and material are declared in JSX, so R3F disposes them when the canvas unmounts.
import { Canvas, useFrame, type RootState } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import { AdditiveBlending, Color, type ShaderMaterial } from "three";

export type SceneVariant = "loading" | "empty" | "ambient";
export type SceneTier = "normal" | "low";

const POINTS: Record<SceneTier, number> = { normal: 1600, low: 640 };
const DPR: Record<SceneTier, [number, number]> = { normal: [1, 1.5], low: [1, 1] };
/** Overall brightness per surface: the ambient background stays far behind its page. */
const INTENSITY: Record<SceneVariant, number> = { loading: 1, empty: 0.8, ambient: 0.6 };
/** Share of the points that flow along the tunnels (the rest is drifting dust). */
const FLOW_SHARE: Record<SceneVariant, number> = { loading: 0.45, empty: 0.3, ambient: 0.3 };
/** The longest step one frame may advance: after a pause the scene continues, it does not jump. */
const MAX_STEP = 1 / 20;
/** Frame-rate watch: after this many seconds of frames slower than SLOW_FRAME, the backdrop falls to the low tier. */
const SLOW_SECONDS = 3;
const SLOW_FRAME = 1 / 40;

const VERTEX = /* glsl */ `
  attribute vec4 aSeed;
  uniform float uTime;
  uniform float uPixelRatio;
  uniform float uFlowShare;
  uniform vec3 uStops[4];
  varying vec3 vColor;
  varying float vAlpha;

  vec3 gradient(float t) {
    float s = clamp(t, 0.0, 1.0) * 3.0;
    if (s < 1.0) return mix(uStops[0], uStops[1], s);
    if (s < 2.0) return mix(uStops[1], uStops[2], s - 1.0);
    return mix(uStops[2], uStops[3], s - 2.0);
  }

  void main() {
    vec3 p;
    float size;
    if (aSeed.w < uFlowShare) {
      // A tunnel: three lanes of light flowing left to right along slow sine paths.
      float lane = floor(aSeed.z * 3.0);
      float t = fract(aSeed.x + uTime * (0.025 + 0.02 * aSeed.y));
      float x = mix(-7.5, 7.5, t);
      float y = (lane - 1.0) * 1.15 + sin(x * 0.55 + lane * 1.9 + uTime * 0.12) * 0.7;
      float spread = (fract(aSeed.y * 13.7) - 0.5) * 0.22;
      p = vec3(x, y + spread, -1.2 - lane * 0.7 + spread);
      vColor = gradient(t);
      vAlpha = sin(t * 3.14159) * (0.55 + 0.45 * fract(aSeed.z * 7.3));
      size = 2.6 + 2.2 * fract(aSeed.x * 5.1);
    } else {
      // Dust: drifts upward and sideways, wraps around, twinkles.
      vec3 base = position;
      base.y = mod(base.y + 3.6 + uTime * 0.05 * (0.4 + aSeed.y), 7.2) - 3.6;
      base.x += sin(uTime * 0.07 + aSeed.x * 6.2831) * 0.35;
      p = base;
      vColor = gradient(aSeed.z);
      vAlpha = 0.25 + 0.35 * (0.5 + 0.5 * sin(uTime * (0.6 + aSeed.y) + aSeed.x * 40.0));
      size = 1.4 + 1.6 * aSeed.y;
    }
    vec4 mv = modelViewMatrix * vec4(p, 1.0);
    gl_Position = projectionMatrix * mv;
    gl_PointSize = size * uPixelRatio * (22.0 / max(-mv.z, 0.5));
  }
`;

const FRAGMENT = /* glsl */ `
  uniform float uIntensity;
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    float d = length(gl_PointCoord - 0.5);
    float a = smoothstep(0.5, 0.0, d);
    a = a * a * vAlpha * uIntensity;
    if (a < 0.003) discard;
    gl_FragColor = vec4(vColor * a, a);
    #include <colorspace_fragment>
  }
`;

/** Brand stops in tokens.css; Color converts the sRGB hex values to the linear working space. */
const STOPS = ["#49cfff", "#3e89ff", "#727dff", "#ab7bff"] as const;

/** A small seeded generator, so the field is the same on every visit. */
function seeded(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function SignalField({
  count,
  variant,
  onDecline,
}: {
  count: number;
  variant: SceneVariant;
  onDecline: (() => void) | undefined;
}) {
  const material = useRef<ShaderMaterial>(null);
  const elapsed = useRef(0);
  const slow = useRef(0);
  const buffers = useMemo(() => {
    const random = seeded(0x5eed);
    const position = new Float32Array(count * 3);
    const seed = new Float32Array(count * 4);
    for (let i = 0; i < count; i += 1) {
      position[i * 3] = (random() - 0.5) * 15;
      position[i * 3 + 1] = (random() - 0.5) * 7.2;
      position[i * 3 + 2] = -0.5 - random() * 4;
      for (let k = 0; k < 4; k += 1) seed[i * 4 + k] = random();
    }
    return { position, seed };
  }, [count]);
  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uPixelRatio: { value: 1 },
      uIntensity: { value: INTENSITY[variant] },
      uFlowShare: { value: FLOW_SHARE[variant] },
      uStops: { value: STOPS.map((hex) => new Color(hex)) },
    }),
    [variant],
  );

  useFrame((state: RootState, delta: number) => {
    const m = material.current;
    if (!m) return;
    elapsed.current += Math.min(delta, MAX_STEP);
    // A falling frame rate (ignoring the long first frame after a pause) asks once for the low tier.
    if (onDecline && delta < 1) {
      slow.current = delta > SLOW_FRAME ? slow.current + delta : Math.max(0, slow.current - delta);
      if (slow.current > SLOW_SECONDS) {
        slow.current = 0;
        onDecline();
      }
    }
    const u = m.uniforms;
    if (u.uTime) u.uTime.value = elapsed.current;
    if (u.uPixelRatio) u.uPixelRatio.value = state.viewport.dpr;
  });

  return (
    <points frustumCulled={false}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[buffers.position, 3]} />
        <bufferAttribute attach="attributes-aSeed" args={[buffers.seed, 4]} />
      </bufferGeometry>
      <shaderMaterial
        ref={material}
        vertexShader={VERTEX}
        fragmentShader={FRAGMENT}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={AdditiveBlending}
      />
    </points>
  );
}

export interface BrandSceneProps {
  variant: SceneVariant;
  tier: SceneTier;
  /** False while the page is hidden or the canvas is offscreen: no frames are rendered. */
  active: boolean;
  /** Frame rate kept falling: the backdrop switches to the low tier. */
  onDecline: () => void;
  /** The WebGL context was lost (driver reset, GPU pressure); the backdrop shows its DOM visual and remounts. */
  onContextLost: () => void;
}

export default function BrandScene({ variant, tier, active, onDecline, onContextLost }: BrandSceneProps) {
  const detach = useRef<(() => void) | null>(null);
  useEffect(
    () => () => {
      detach.current?.();
      detach.current = null;
    },
    [],
  );
  return (
    <Canvas
      dpr={DPR[tier]}
      frameloop={active ? "always" : "never"}
      camera={{ position: [0, 0, 6], fov: 50, near: 0.1, far: 30 }}
      gl={{ alpha: true, antialias: false, powerPreference: "low-power", premultipliedAlpha: true }}
      style={{ pointerEvents: "none" }}
      onCreated={({ gl }) => {
        gl.setClearColor(0x000000, 0);
        const canvas = gl.domElement;
        const lost = (event: Event) => {
          event.preventDefault();
          onContextLost();
        };
        canvas.addEventListener("webglcontextlost", lost);
        detach.current = () => {
          canvas.removeEventListener("webglcontextlost", lost);
        };
      }}
    >
      <SignalField count={POINTS[tier]} variant={variant} onDecline={tier === "normal" ? onDecline : undefined} />
    </Canvas>
  );
}
