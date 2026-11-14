// The notice above the views while recording is not as usual: the oldest data overwritten on a low or full disk, or
// samples that cannot be written (recordingNotice). It comes and goes with a fast fade (Motion presence; already there
// when the page opens, it is shown at once), and its relative times tick here, never in the page.

import { HardDrive } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import type { MetricsRecording } from "@/api/types";
import { SectionLink } from "@/components/ui/inspector";
import { usePresenceInert } from "@/components/ui/motion";
import { swapVariants } from "@/components/ui/motion-tokens";
import { Callout } from "@/components/ui/states";
import { useServerNow } from "@/lib/server-clock";
import { type RecordingNotice as Notice, recordingNotice } from "./model";

function Strip({ notice }: { notice: Notice }) {
  const { props } = usePresenceInert();
  return (
    <motion.div
      {...props}
      role="status"
      variants={swapVariants()}
      initial="hidden"
      animate="shown"
      exit="gone"
      className="shrink-0 border-b border-line-subtle px-4 py-2 md:px-6"
    >
      <Callout
        tone={notice.tone}
        title={notice.title}
        actions={
          <SectionLink to="/system?view=runtime" icon={HardDrive}>
            {notice.action}
          </SectionLink>
        }
      >
        <p className="[overflow-wrap:anywhere]">{notice.detail}</p>
      </Callout>
    </motion.div>
  );
}

export function RecordingNotice({ recording }: { recording: MetricsRecording | null | undefined }) {
  const now = useServerNow();
  const notice = recordingNotice(recording, now);
  return <AnimatePresence initial={false}>{notice ? <Strip key="notice" notice={notice} /> : null}</AnimatePresence>;
}
