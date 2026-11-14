// A line of short facts separated by " · " that wraps only between facts: "Not downloaded yet" or "1 connection" stays
// whole on a line, and only a fact wider than the whole line wraps inside.
import { Fragment } from "react";

export function FactLine({ items }: { items: readonly string[] }) {
  return (
    <>
      {items.map((fact, i) => (
        <Fragment key={`${String(i)}:${fact}`}>
          {i ? " · " : ""}
          <span className="inline-block max-w-full">{fact}</span>
        </Fragment>
      ))}
    </>
  );
}
