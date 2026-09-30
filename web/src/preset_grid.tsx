// PresetGrid: the permission presets as one grid — a preset a row, a permission a column, a checkbox
// where they meet. It replaced a checkbox per line with its scope id on a line under it, which made
// four presets a page long (owner, 2026-09-30). Shared with PACT Cloud's portal byte for byte
// (scripts/check-harvested.mjs there). Both portals keep a row's ticks as a draft (usePresetDrafts) until
// the row's Save; the save itself is each portal's own call, passed in as a row's `actions`.
//
//   - The columns are presets.ts's presetColumns: the vocabulary, then anything a preset holds that
//     it lacks — never a fixed list here.
//   - A column's heading is the permission's name; its scope id (`message.text`) is behind the `?`
//     beside it (help.tsx) and in the heading's title.
//   - Every checkbox is a real <input type="checkbox"> named "<preset>: <permission>" (presets.ts's
//     cellLabel), inside a <label>, so a click anywhere on it toggles it and a keyboard reaches it.
//   - The grid scrolls inside its own box when it is wider than the page, never the page itself. On a
//     phone (style.css, ≤480px) the head is hidden and each preset is a card of wrapping chips, each
//     chip the same checkbox with the permission's name beside it and the scope id in its title.
import { useState, type ReactNode } from "react";
import { HelpTip } from "./help";
import { cellLabel, samePerms, withPerm, type GridPreset } from "./presets";

/**
 * The grid's rows as drafts: a click changes a row's draft, never what is saved, until the row's Save
 * (both portals: a stray tap on a phone's chip grants nothing). `perms` is what a row shows, `changed`
 * whether its Save has anything to do, `toggle` the grid's onToggle, and `settle` drops a row's draft
 * once its save is answered — kept on a failure, so the ticks the owner made are still there to retry.
 * A row that is not saved yet (a new preset) is a name `saved` does not hold.
 */
export function usePresetDrafts(saved: readonly GridPreset[]) {
  const [drafts, setDrafts] = useState<Readonly<Record<string, readonly string[]>>>({});
  const savedOf = (name: string) => saved.find((p) => p.name === name)?.perms ?? [];
  return {
    perms: (name: string): readonly string[] => drafts[name] ?? savedOf(name),
    changed: (name: string) => name in drafts && !samePerms(drafts[name], savedOf(name)),
    toggle: (name: string, perm: string, on: boolean) => setDrafts((all) => ({ ...all, [name]: withPerm(all[name] ?? savedOf(name), perm, on) })),
    settle: (name: string) => setDrafts(({ [name]: _settled, ...rest }) => rest),
  };
}

export type GridRow = {
  /** The preset's name, as its checkboxes are called ("New preset" for a row not yet named). */
  name: string;
  /** What the row's first cell shows; the name when absent. */
  title?: ReactNode;
  /** A line under the title ("yours, not the default"). */
  note?: ReactNode;
  perms: readonly string[];
  /** The row's buttons (Save, Delete), in its last cell. */
  actions?: ReactNode;
};

export function PresetGrid({ rows, columns, label, onToggle, "aria-label": aria }: {
  rows: GridRow[];
  columns: readonly string[];
  /** A permission's name as an owner reads it (words.ts permLabel). */
  label: (perm: string) => string;
  onToggle: (preset: string, perm: string, on: boolean) => void;
  "aria-label": string;
}) {
  const acts = rows.some((r) => r.actions);
  return (
    <div className="table-wrap preset-grid" role="region" aria-label={aria} tabIndex={0}>
      <table>
        <thead>
          <tr>
            <th scope="col">Preset</th>
            {columns.map((c) => (
              <th key={c} scope="col" className="pg-col">
                <span className="pg-h" title={c}>{label(c)}</span>
                <HelpTip label={`About ${label(c)}`}>Grants the <code>{c}</code> scope.</HelpTip>
              </th>
            ))}
            {acts && <th className="actions" aria-label="Actions" />}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const on = new Set(r.perms);
            return (
              <tr key={r.name}>
                <th scope="row" className="pg-name">
                  {r.title ?? r.name}
                  {r.note && <span className="pg-note">{r.note}</span>}
                </th>
                {columns.map((c) => (
                  <td key={c} className="pg-cell">
                    <label className="pg-chip" title={c}>
                      <input type="checkbox" checked={on.has(c)} aria-label={cellLabel(r.name, label(c))}
                        onChange={(e) => onToggle(r.name, c, e.target.checked)} />
                      <span className="pg-chip-t" aria-hidden="true">{label(c)}</span>
                    </label>
                  </td>
                ))}
                {acts && <td className="pg-acts">{r.actions}</td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
