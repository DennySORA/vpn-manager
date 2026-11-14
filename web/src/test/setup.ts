import { cleanup } from "@testing-library/react";
import { MotionGlobalConfig } from "motion/react";
import { afterEach } from "vitest";

// The tests read the Traditional Chinese text. The language is fixed when `@/i18n` first loads, so the choice is
// stored here, before any test file imports the application.
window.localStorage.setItem("vpnm.choice.locale", "zh-TW");

// Tests assert states, not animation: Motion only presents state, and a state never waits for an animation. The test
// DOM has no real animation engine, so Motion skips straight to each animation's end (exits complete at once).
MotionGlobalConfig.skipAnimations = true;

afterEach(() => {
  cleanup();
});
