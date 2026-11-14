// A value that changes in place — a count, "1/3 受保護", a step that is now done, a status chip's icon and words: the
// content is keyed by the value inside AnimatePresence (initial={false}), so the first render shows it at once and each
// change cross-fades on the fast transition (swapVariants). The leaving copy pops out of the layout (popLayout), is
// inert and hidden from assistive technology; the latest value is always in place at once. Not for live readings that
// change every second (rates, times): linear things stay linear, and they would flicker.
import { AnimatePresence, motion } from "motion/react";
import type { ReactNode, Ref } from "react";
import { usePresenceInert } from "./motion";
import { swapVariants } from "./motion-tokens";

const TAGS = { span: motion.span, div: motion.div, p: motion.p } as const;

/** One copy of the value; the ref reaches its element so popLayout can take the leaving copy out of the layout. */
function FadeCopy({
  as,
  className,
  children,
  ref,
}: {
  as: keyof typeof TAGS;
  className?: string | undefined;
  children: ReactNode;
  ref?: Ref<HTMLSpanElement> | undefined;
}) {
  const { props } = usePresenceInert();
  // One element type for the ref: the three tags share every prop used here.
  const Tag = TAGS[as] as typeof motion.span;
  return (
    <Tag
      ref={ref}
      {...props}
      variants={swapVariants()}
      initial="hidden"
      animate="shown"
      exit="gone"
      className={className}
    >
      {children}
    </Tag>
  );
}

/** `children` fades in whenever `value` changes (never on the first render). */
export function ChangeFade({
  value,
  children,
  className,
  as = "span",
}: {
  value: unknown;
  children: ReactNode;
  className?: string | undefined;
  as?: keyof typeof TAGS | undefined;
}) {
  return (
    <AnimatePresence initial={false} mode="popLayout">
      <FadeCopy key={String(value)} as={as} className={className}>
        {children}
      </FadeCopy>
    </AnimatePresence>
  );
}

export function ChangeValue({
  value,
  children,
  className,
}: {
  value: unknown;
  children?: ReactNode | undefined;
  className?: string | undefined;
}) {
  return (
    <ChangeFade value={value} className={className}>
      {children ?? String(value)}
    </ChangeFade>
  );
}
