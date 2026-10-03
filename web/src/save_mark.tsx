// The pieces a control that saves itself shows beside what it saved: a spinner while the save is out,
// a check when it is kept, and an Undo while the step back is on offer (the presets grid's rows,
// preset_grid.tsx). Shared with BatonDeck's portal byte for byte (scripts/check-harvested.mjs there),
// so both portals draw a save in progress, and a save done, the same way. The looks are style.css's
// (`.spinner`, `.save-mark`), from the theme's tokens; nothing here names a colour.
import { Button, Icon } from "./ui";

/**
 * A spinner: a ring turning while something is at work. `label` says what, to a screen reader; without
 * one it is decoration beside words that say it. With reduced motion asked for it stands still
 * (style.css), a ring with one arc in the accent.
 */
export function Spinner({ label }: { label?: string }) {
  return label
    ? <span className="spinner" role="img" aria-label={label} />
    : <span className="spinner" aria-hidden="true" />;
}

/**
 * What a row that saves itself shows where a Save button would be. `phase` is the row's moment
 * (presets.ts RowPhase: `saving` a spinner, `saved` a check that fades); `what` names the thing saved,
 * in the spinner's label, the Undo's name and the announcement; `onUndo`, when given, is the Undo
 * button. The announcement ("Saved basic") is a live region that is there before it has words, so a
 * screen reader hears it arrive.
 */
export function SaveMark({ phase, what, onUndo }: { phase: "idle" | "waiting" | "saving" | "saved"; what: string; onUndo?: () => void }) {
  return (
    <span className="save-mark">
      {phase === "saving" && <Spinner label={`Saving ${what}`} />}
      {phase === "saved" && <span className="save-done"><Icon name="check" size={16} /></span>}
      {onUndo && <Button variant="quiet" icon="undo" aria-label={`Undo ${what}`} title={`Put ${what} back as it was before this save`} onClick={onUndo} />}
      <span className="sr-only" role="status" aria-live="polite">{phase === "saved" ? `Saved ${what}` : ""}</span>
    </span>
  );
}
