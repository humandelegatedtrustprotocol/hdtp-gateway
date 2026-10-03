// The help tip's behaviour, with no DOM and no JSX, so web/test/helptip_test.mjs runs it under plain
// `node --test` (make test-js). help.tsx is the component that drives it. Both are shared with HDTP
// Cloud's portal byte for byte (its scripts/check-harvested.mjs holds the copies to this repository's).
//
// A tip opens on hover (a mouse only: a touch tap synthesises an enter with no leave), on keyboard
// focus, and on a click or tap; Escape closes it, and so does a press outside it. A click on a tip
// that hover or focus opened pins it open; a click on a pinned tip closes it — so on a phone the
// first tap opens and the second closes, and on a desktop a click keeps what hover showed.

export type TipState = { hover: boolean; focus: boolean; pinned: boolean; dismissed: boolean };
export type TipEvent = "enter" | "leave" | "focus" | "blur" | "click" | "escape" | "outside";

export const TIP_CLOSED: TipState = { hover: false, focus: false, pinned: false, dismissed: false };

/** Whether the tip is showing. */
export function tipOpen(s: TipState): boolean {
  return !s.dismissed && (s.hover || s.focus || s.pinned);
}

/** The next state. Escape and a second click dismiss it until the next enter, focus or click. */
export function tipReduce(s: TipState, e: TipEvent): TipState {
  switch (e) {
    case "enter": return { ...s, hover: true, dismissed: false };
    case "leave": return { ...s, hover: false };
    case "focus": return { ...s, focus: true, dismissed: false };
    case "blur": return { ...s, focus: false, pinned: false };
    case "click": return tipOpen(s) && s.pinned ? { ...s, pinned: false, dismissed: true } : { ...s, pinned: true, dismissed: false };
    case "escape": return { ...s, pinned: false, dismissed: true };
    case "outside": return { ...s, hover: false, pinned: false };
  }
}

export type Box = { top: number; bottom: number; left: number; right: number };

/**
 * Where the popover goes, in viewport coordinates (it is `position:fixed`): under its button when it
 * fits there or has more room there, else above; centred on the button, and never closer than
 * `margin` to an edge of the viewport — so at 320px it stays whole on the screen.
 */
export function tipPlace(anchor: Box, tip: { width: number; height: number }, view: { width: number; height: number }, gap = 6, margin = 8): { top: number; left: number; side: "below" | "above" } {
  const centre = (anchor.left + anchor.right) / 2;
  const maxLeft = Math.max(margin, view.width - margin - tip.width);
  const left = Math.min(Math.max(centre - tip.width / 2, margin), maxLeft);
  const below = view.height - anchor.bottom - gap - margin;
  const above = anchor.top - gap - margin;
  const side = tip.height <= below || below >= above ? "below" : "above";
  const raw = side === "below" ? anchor.bottom + gap : anchor.top - gap - tip.height;
  const top = Math.max(margin, Math.min(raw, view.height - margin - tip.height));
  return { top: Math.round(top), left: Math.round(left), side };
}
