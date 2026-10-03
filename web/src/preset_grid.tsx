// PresetGrid: the permission presets as one grid — a preset a row, a permission a column, a checkbox
// where they meet. It replaced a checkbox per line with its scope id on a line under it, which made
// four presets a page long (owner, 2026-09-30). Shared with BatonDeck's portal byte for byte
// (scripts/check-harvested.mjs there). A row saves itself (usePresetAutosave, presets.ts
// presetAutosave): a tick changes it at once and it saves when the ticks stop, a spinner where a Save
// button used to be, then a check and an Undo (save_mark.tsx); the save itself is each portal's own
// call (the node's POST, the cloud's PATCH), passed to the hook.
//
//   - The columns are presets.ts's presetColumns: the vocabulary, then anything a preset holds that
//     it lacks — never a fixed list here.
//   - A column's heading is the permission's name; its scope id (`message.text`) is behind the `?`
//     beside it (help.tsx) and in the heading's title.
//   - Every checkbox is a real <input type="checkbox"> named "<preset>: <permission>" (presets.ts's
//     cellLabel), inside a <label>, so a click anywhere on it toggles it and a keyboard reaches it. A
//     row's checkboxes are disabled while its save is out.
//   - A refused save puts the row back as it is saved and says why on a line under it (`failure`,
//     each portal's own way of saying a refusal), until the row's next tick.
//   - The grid scrolls inside its own box when it is wider than the page, never the page itself. On a
//     phone (style.css, ≤480px) the head is hidden and each preset is a card of wrapping chips, each
//     chip the same checkbox with the permission's name beside it and the scope id in its title.
import { Fragment, useEffect, useReducer, useRef, useState, type ReactNode } from "react";
import { HelpTip } from "./help";
import { cellLabel, presetAutosave, type GridPreset } from "./presets";
import { SaveMark } from "./save_mark";

/**
 * The grid's rows, saving themselves: presets.ts's presetAutosave, held for the life of the grid and
 * redrawn on each change. `saved` is what the portal last read; `save(name, perms)` is the portal's
 * call, resolving once `saved` has been updated from the answer and rejecting with the reason. `perms`
 * is what a row shows; `forget` drops a row's draft once the portal has added or deleted it by its own
 * button.
 */
export function usePresetAutosave(saved: readonly GridPreset[], save: (name: string, perms: readonly string[]) => Promise<void>) {
  const [, redraw] = useReducer((n: number) => n + 1, 0);
  const latest = useRef({ saved, save });
  useEffect(() => { latest.current = { saved, save }; });
  const [rows] = useState(() => presetAutosave({ saved: () => latest.current.saved, save: (n, p) => latest.current.save(n, p), changed: redraw }));
  useEffect(() => () => rows.dispose(), [rows]);
  return {
    perms: (name: string) => rows.perms(name, saved),
    state: rows.state,
    toggle: rows.toggle,
    undo: rows.undo,
    forget: rows.forget,
    /** Whether a row saves itself: a preset `saved` holds. */
    saves: (name: string) => saved.some((p) => p.name === name),
  };
}

export type PresetAutosave = ReturnType<typeof usePresetAutosave>;

export type GridRow = {
  /** The preset's name, as its checkboxes are called ("New preset" for a row not yet named). */
  name: string;
  /** What the row's first cell shows; the name when absent. */
  title?: ReactNode;
  /** A line under the title ("yours, not the default"). */
  note?: ReactNode;
  perms: readonly string[];
  /** The row's buttons (the node's Delete, its new preset's Add), in its last cell after the save's mark. */
  actions?: ReactNode;
};

export function PresetGrid({ rows, columns, label, autosave, failure, "aria-label": aria }: {
  rows: GridRow[];
  columns: readonly string[];
  /** A permission's name as an owner reads it (words.ts permLabel). */
  label: (perm: string) => string;
  /** The rows' saves (usePresetAutosave): each row's moment, and what a tick does. */
  autosave: PresetAutosave;
  /** A refused save, as the portal says a refusal (its Notice), under the row it was for. */
  failure: (preset: string, error: unknown) => ReactNode;
  "aria-label": string;
}) {
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
            <th className="actions" aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const on = new Set(r.perms);
            const st = autosave.state(r.name);
            const saving = st.phase === "saving";
            return (
              <Fragment key={r.name}>
                <tr className={saving ? "pg-saving" : undefined}>
                  <th scope="row" className="pg-name">
                    {r.title ?? r.name}
                    {r.note && <span className="pg-note">{r.note}</span>}
                  </th>
                  {columns.map((c) => (
                    <td key={c} className="pg-cell">
                      <label className="pg-chip" title={c}>
                        <input type="checkbox" checked={on.has(c)} disabled={saving} aria-label={cellLabel(r.name, label(c))}
                          onChange={(e) => autosave.toggle(r.name, c, e.target.checked)} />
                        <span className="pg-chip-t" aria-hidden="true">{label(c)}</span>
                      </label>
                    </td>
                  ))}
                  <td className="pg-acts">
                    {autosave.saves(r.name) && <SaveMark phase={st.phase} what={r.name} onUndo={st.undo ? () => autosave.undo(r.name) : undefined} />}
                    {r.actions}
                  </td>
                </tr>
                {st.error !== null && (
                  <tr className="pg-fail">
                    <td colSpan={columns.length + 2}>{failure(r.name, st.error)}</td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
