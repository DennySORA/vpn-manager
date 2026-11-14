// The sort order of a collection, in its tool strip: a 28 px tool button naming the current order opens a menu of the
// orders (menuitemradio: arrow keys, Enter, the chosen one checked). The order lives in the URL with the filters; the
// rows then slide to their new places (table.tsx TBody).
import { ArrowDownUp } from "lucide-react";
import { Menu, MenuRadioGroup, MenuRadioItem } from "./menu";
import { m } from "./messages";
import { ToolButton } from "./tool-strip";

export function SortMenu<V extends string>({
  value,
  options,
  onChange,
  label = m.sort.label,
}: {
  value: V;
  options: readonly { value: V; label: string }[];
  onChange: (value: V) => void;
  label?: string | undefined;
}) {
  const current = options.find((o) => o.value === value) ?? options[0];
  return (
    <Menu
      align="end"
      label={label}
      trigger={
        <ToolButton
          label={m.sort.current(label, current?.label ?? "")}
          icon={<ArrowDownUp aria-hidden />}
          text={
            <>
              <span className="sr-only">{m.sort.lead(label)}</span>
              {current?.label}
            </>
          }
        />
      }
    >
      <MenuRadioGroup value={value} onValueChange={onChange} label={label}>
        {options.map((o) => (
          <MenuRadioItem key={o.value} value={o.value}>
            {o.label}
          </MenuRadioItem>
        ))}
      </MenuRadioGroup>
    </Menu>
  );
}
