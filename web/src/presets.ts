// The permission presets' grid (preset_grid.tsx), its arithmetic: which columns it draws, what each
// checkbox is called, whether a row has changed, and how a row saves itself (presetAutosave). Shared
// with PACT Cloud's portal byte for byte (scripts/check-harvested.mjs there), so both portals draw one
// grid from one rule.

/** A preset as the grid reads it: its name and the permissions it grants. */
export type GridPreset = { name: string; perms: readonly string[] };

/**
 * The grid's columns: the vocabulary, in its order, then every permission a preset already holds
 * that the vocabulary lacks, in the order first seen. Both portals save a preset as its whole list,
 * so a permission the grid did not draw would be dropped by the next save of that row.
 */
export function presetColumns(vocab: readonly string[], presets: readonly GridPreset[]): string[] {
  const out = [...new Set(vocab)];
  const seen = new Set(out);
  for (const p of presets) for (const x of p.perms) if (!seen.has(x)) { seen.add(x); out.push(x); }
  return out;
}

/** A checkbox's accessible name: the preset's and the permission's, "basic: Messages". */
export function cellLabel(preset: string, permission: string): string {
  return `${preset}: ${permission}`;
}

/** `perms` with `perm` switched on or off, each once, in the order they were. */
export function withPerm(perms: readonly string[], perm: string, on: boolean): string[] {
  const rest = perms.filter((x) => x !== perm);
  return on ? [...rest, perm] : rest;
}

/** Whether two grants hold the same permissions, order aside. */
export function samePerms(a: readonly string[], b: readonly string[]): boolean {
  const x = new Set(a), y = new Set(b);
  return x.size === y.size && [...x].every((p) => y.has(p));
}

/**
 * How long a row waits after its last tick before it saves itself (a burst of ticks is one save), how
 * long its check stays after a save, and how long its Undo is offered.
 */
export const AUTOSAVE = { debounceMs: 800, savedMs: 1500, undoMs: 6000 } as const;

/**
 * A row's moment. `waiting`: ticked, its save due when the ticks stop (or queued behind another row's).
 * `saving`: its request is out — its checkboxes are disabled until it is answered. `saved`: answered
 * yes, the check shown for AUTOSAVE.savedMs.
 */
export type RowPhase = "idle" | "waiting" | "saving" | "saved";

/**
 * A row as the grid draws it. `undo` is what the row held before its last save, offered for
 * AUTOSAVE.undoMs (null when there is nothing to undo). `error` is why its last save was refused — the
 * row is back on what is saved, and the reason stays until the row's next tick.
 */
export type RowState = { phase: RowPhase; undo: readonly string[] | null; error: unknown };

/** The clock the rows run on: the page's, or a test's. */
export type Clock = { set: (fn: () => void, ms: number) => unknown; clear: (handle: unknown) => void };

const IDLE: RowState = { phase: "idle", undo: null, error: null };

/**
 * The presets grid's autosave: a tick changes a row at once, and the row saves itself AUTOSAVE.debounceMs
 * after its last tick, through the portal's own `save` (the node's POST, the cloud's PATCH), which
 * resolves once what is saved has been updated and rejects with the reason when it was refused.
 *
 *   - One save at a time, in the order they came due: the node answers a save with the whole page, so
 *     an answer overtaken by a later one would put the older rows back.
 *   - A row that ends a burst where it started sends nothing.
 *   - A row `saved` does not hold (the node's new preset, not named yet) is a draft only: it is added by
 *     its own button, which then `forget`s it.
 *   - On success the row shows what is saved, the check, and an Undo back to what it held before; the
 *     Undo is saved the same way, at once (it is one deliberate press, not a burst).
 *   - On a refusal the row goes back to what is saved, and keeps the reason.
 *
 * `saved` and `save` are read when they are needed, so a portal can pass its latest each render.
 * `changed` is called after every change a grid would draw.
 */
export function presetAutosave(o: {
  saved: () => readonly GridPreset[];
  save: (name: string, perms: readonly string[]) => Promise<void>;
  changed: () => void;
  clock?: Clock;
}) {
  const clock: Clock = o.clock ?? { set: (fn, ms) => setTimeout(fn, ms), clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>) };
  const drafts = new Map<string, readonly string[]>();
  const rows = new Map<string, RowState>();
  const timers = new Map<string, unknown[]>();
  const queue: string[] = [];
  let busy = false;

  const savedOf = (name: string, list = o.saved()) => list.find((p) => p.name === name)?.perms;
  const state = (name: string): RowState => rows.get(name) ?? IDLE;
  const set = (name: string, s: Partial<RowState>) => rows.set(name, { ...state(name), ...s });
  // A row's clocks, and its place in the queue: a tick after its save came due starts its wait again.
  const stop = (name: string) => {
    for (const h of timers.get(name) ?? []) clock.clear(h);
    timers.delete(name);
    const at = queue.indexOf(name);
    if (at >= 0) queue.splice(at, 1);
  };
  const after = (name: string, ms: number, fn: () => void) => { timers.set(name, [...(timers.get(name) ?? []), clock.set(fn, ms)]); };

  const next = () => {
    if (busy) return;
    const name = queue.shift();
    if (name === undefined) return;
    const was = savedOf(name);
    const perms = drafts.get(name);
    if (was === undefined || perms === undefined || samePerms(perms, was)) {
      // Nothing to send: deleted meanwhile, or ticked back to where it was.
      drafts.delete(name);
      if (state(name).phase === "waiting") set(name, { phase: "idle" });
      o.changed();
      next();
      return;
    }
    busy = true;
    set(name, { phase: "saving", undo: null, error: null });
    o.changed();
    o.save(name, perms).then(
      () => {
        drafts.delete(name);
        set(name, { phase: "saved", undo: was, error: null });
        after(name, AUTOSAVE.savedMs, () => { if (state(name).phase === "saved") { set(name, { phase: "idle" }); o.changed(); } });
        after(name, AUTOSAVE.undoMs, () => { set(name, { undo: null }); o.changed(); });
      },
      (error: unknown) => {
        // Back to what is saved: a refusal is never left drawn as if it had been kept.
        drafts.delete(name);
        set(name, { phase: "idle", undo: null, error: error ?? new Error("refused") });
      },
    ).finally(() => {
      busy = false;
      o.changed();
      next();
    });
  };

  const due = (name: string) => {
    if (!queue.includes(name)) queue.push(name);
    next();
  };

  return {
    /** What a row shows: its draft, else what is saved. */
    perms: (name: string, saved: readonly GridPreset[]): readonly string[] => drafts.get(name) ?? savedOf(name, saved) ?? [],
    state,
    /** A tick: the row changes now, and (for a saved preset) saves itself when the ticks stop. */
    toggle: (name: string, perm: string, on: boolean) => {
      if (state(name).phase === "saving") return;
      const was = savedOf(name);
      drafts.set(name, withPerm(drafts.get(name) ?? was ?? [], perm, on));
      if (was !== undefined) {
        stop(name);
        set(name, { phase: "waiting", undo: null, error: null });
        after(name, AUTOSAVE.debounceMs, () => due(name));
      }
      o.changed();
    },
    /** The row back to what it held before its last save, saved at once. */
    undo: (name: string) => {
      const back = state(name).undo;
      if (!back || state(name).phase === "saving") return;
      stop(name);
      drafts.set(name, back);
      set(name, { phase: "waiting", undo: null, error: null });
      o.changed();
      due(name);
    },
    /** Drop a row's draft and moment: the row was added by its own button, or deleted. */
    forget: (name: string) => {
      stop(name);
      drafts.delete(name);
      rows.delete(name);
      o.changed();
    },
    /** Stop every clock (the grid left the page); a request already out is still answered. */
    dispose: () => { for (const name of [...timers.keys()]) stop(name); },
  };
}
