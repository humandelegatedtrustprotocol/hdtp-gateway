// The permission presets' grid (preset_grid.tsx), its arithmetic: which columns it draws, what each
// checkbox is called, and whether a row has changed. Shared with PACT Cloud's portal byte for byte
// (scripts/check-harvested.mjs there), so both portals draw one grid from one rule.

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
