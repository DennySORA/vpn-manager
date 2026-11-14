import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Development: the controller runs with `--dev-origin http://localhost:5173`; this proxy keeps the
// browser same-origin. Production assets are embedded into vpnd (Web Provide Service).
const controller = process.env.VPN_CONTROLLER ?? "http://127.0.0.1:28765";

// VPN_CONTROLLER_READONLY=1: only GET and HEAD reach the controller, so the UI under development can show an installed
// VPN Manager's real data without being able to change it. Every other method is answered 404 by the dev server
// itself and never reaches the controller.
const readOnly = process.env.VPN_CONTROLLER_READONLY === "1";
const proxyTo = (target: string) => ({
  target,
  changeOrigin: true,
  ...(readOnly
    ? {
        bypass: (req: { method?: string | undefined }) =>
          req.method === "GET" || req.method === "HEAD" ? undefined : false,
      }
    : {}),
});

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    host: "localhost",
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": proxyTo(controller),
      "/healthz": proxyTo(controller),
    },
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    target: "es2023",
    // The brand scene's three.js chunk (lazy, brand moments only) is the one large file; everything on the first
    // paint stays well under this.
    chunkSizeWarningLimit: 960,
    rolldownOptions: {
      output: {
        // Long-lived vendor chunks: an app update re-downloads only the app's own code. Each group is loaded only by
        // the code that imports it (three.js stays with the lazily loaded brand scene).
        codeSplitting: {
          groups: [
            { name: "vendor-react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/, priority: 40 },
            { name: "vendor-router", test: /node_modules[\\/]react-router[\\/]/, priority: 30 },
            { name: "vendor-query", test: /node_modules[\\/]@tanstack[\\/]/, priority: 30 },
            {
              name: "vendor-motion",
              test: /node_modules[\\/](motion|motion-dom|motion-utils|framer-motion)[\\/]/,
              priority: 30,
            },
            {
              name: "vendor-radix",
              test: /node_modules[\\/](radix-ui|@radix-ui|@floating-ui|react-remove-scroll[^\\/]*|aria-hidden|use-callback-ref|use-sidecar|react-style-singleton|get-nonce|tslib)[\\/]/,
              priority: 20,
            },
            { name: "vendor-icons", test: /node_modules[\\/]lucide-react[\\/]/, priority: 20 },
          ],
        },
      },
    },
  },
});
