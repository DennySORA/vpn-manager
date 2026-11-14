import "./styles/app.css";
import { QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router/dom";
import { queryClient } from "./api/query-client";
import { router } from "./app/router";
import { motionKit } from "./components/ui/motion-tokens";
import { Toaster } from "./components/ui/toast";
import { TooltipProvider } from "./components/ui/tooltip";

const root = document.getElementById("root");
if (!root) throw new Error("#root missing");

// Motion's default is the smooth spring from tokens.css; motion is always on (no reduced-motion branch).
createRoot(root).render(
  <StrictMode>
    <MotionConfig transition={motionKit().smooth} reducedMotion="never">
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <RouterProvider router={router} />
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </MotionConfig>
  </StrictMode>,
);
