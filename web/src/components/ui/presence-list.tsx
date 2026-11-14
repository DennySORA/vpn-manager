// A list whose items come and go (a connection's proxy ports, the overview's "需要處理", topology lanes), on Motion:
// AnimatePresence with the items' stable keys. Items of the first render rise in one after another (riseVariants, the
// index as `custom`); an item that joins later rises in alone, at once. Data updates never replay an entrance (the
// keys keep the items mounted). An item that leaves fades out in place — inert and hidden from assistive technology
// from the start of its exit — and when it is gone the others glide to their new places (Motion layout="position",
// measured only when the keys change or an exit completes). The data is never delayed. The table counterpart is
// table.tsx's TBody.
import { AnimatePresence, motion } from "motion/react";
import type { ReactNode } from "react";
import { useState } from "react";
import { cn } from "@/lib/cn";
import { usePresenceInert } from "./motion";
import { layoutTransition, riseVariants } from "./motion-tokens";

function PresenceItem({
  stagger,
  layoutDependency,
  className,
  children,
}: {
  /** The stagger index of its entrance (its place when it appeared; 0 for an item that joined later). */
  stagger: number;
  layoutDependency: string;
  className?: string | undefined;
  children: (exiting: boolean) => ReactNode;
}) {
  const { exiting, props } = usePresenceInert();
  return (
    <motion.li
      {...props}
      data-exiting={exiting || undefined}
      layout="position"
      layoutDependency={layoutDependency}
      transition={layoutTransition()}
      variants={riseVariants()}
      custom={stagger}
      initial="hidden"
      animate="shown"
      exit="gone"
      className={cn(className, exiting && "pointer-events-none")}
    >
      {children(exiting)}
    </motion.li>
  );
}

export function PresenceList<T>({
  items,
  keyOf,
  children,
  className,
  itemClassName,
  label,
  as: List = "ul",
}: {
  items: readonly T[];
  keyOf: (item: T) => string;
  children: (item: T, state: { index: number; exiting: boolean }) => ReactNode;
  className?: string | undefined;
  /** Classes of each <li> (layout); the entrance and exit are Motion's. */
  itemClassName?: string | undefined;
  /** The list's accessible name. */
  label?: string | undefined;
  /** "ol" when the order means something (e.g. resolvers tried in order); moving an item glides it. */
  as?: "ul" | "ol" | undefined;
}) {
  const keys = items.map(keyOf);
  // Items of the first render enter as a staggered group; later ones on their own.
  const [firstKeys] = useState(() => new Set(keys));
  // Bumped when exits complete, so the remaining items measure and glide into the freed place.
  const [settled, setSettled] = useState(0);
  const layoutDependency = `${keys.join("\u0000")}#${String(settled)}`;
  return (
    <List aria-label={label} className={className}>
      <AnimatePresence
        onExitComplete={() => {
          setSettled((n) => n + 1);
        }}
      >
        {items.map((item, index) => {
          const key = keys[index] ?? keyOf(item);
          return (
            <PresenceItem
              key={key}
              stagger={firstKeys.has(key) ? index : 0}
              layoutDependency={layoutDependency}
              className={itemClassName}
            >
              {(exiting) => children(item, { index, exiting })}
            </PresenceItem>
          );
        })}
      </AnimatePresence>
    </List>
  );
}
