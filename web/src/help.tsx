// HelpTip: the `?` beside a control or a heading, and the one place a page's longer explanation
// lives. A page says what a control does in a short line; the why, the edge cases and the mechanism
// go in here. Shared with BatonDeck's portal byte for byte (scripts/check-harvested.mjs there), so
// both portals have one tip: its behaviour is helptip.ts, its looks are style.css's `.tip-*`.
//
//   - A real <button type="button">, so it takes keyboard focus and a tap; it never submits a form.
//   - The popover opens on hover (a mouse), on focus, and on click or tap; Escape closes it, and so
//     does a press outside it (helptip.ts has the rules).
//   - The popover is always in the document, `hidden` while closed, and the button names it with
//     `aria-describedby` — so a screen reader reads the explanation on focus without opening anything.
//   - It is `position:fixed`, portalled to <body>: it takes no space in the page (no layout shift),
//     a table's scroll box does not clip it, and tipPlace keeps it inside the viewport at 320px.
//   - Text and <code> only: role="tooltip" holds nothing a person must click. A link stays on the page.
//   - Never put it inside a <label> (a click would toggle the checkbox) or a <summary> (it would
//     toggle the disclosure).
import { useCallback, useEffect, useId, useLayoutEffect, useReducer, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { TIP_CLOSED, tipOpen, tipPlace, tipReduce } from "./helptip";

export function HelpTip({ label = "More information", children }: { label?: string; children: ReactNode }) {
  const [state, send] = useReducer(tipReduce, TIP_CLOSED);
  const open = tipOpen(state);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const pop = useRef<HTMLSpanElement>(null);
  const [at, setAt] = useState<{ top: number; left: number; side: string } | null>(null);
  const leaving = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const place = useCallback(() => {
    const b = btn.current, p = pop.current;
    if (!b || !p) return;
    const r = p.getBoundingClientRect();
    setAt(tipPlace(b.getBoundingClientRect(), { width: r.width, height: r.height }, { width: window.innerWidth, height: window.innerHeight }));
  }, []);

  useLayoutEffect(() => {
    if (!open) { setAt(null); return; }
    place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") send("escape"); };
    const away = (e: Event) => {
      const t = e.target as Node;
      if (!btn.current?.contains(t) && !pop.current?.contains(t)) send("outside");
    };
    document.addEventListener("keydown", esc);
    document.addEventListener("pointerdown", away);
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      document.removeEventListener("keydown", esc);
      document.removeEventListener("pointerdown", away);
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open, place]);
  useEffect(() => () => clearTimeout(leaving.current), []);

  // Hover is a mouse's: the pointer may cross the gap to the popover (and read it there) without it closing.
  const enter = (e: { pointerType: string }) => { if (e.pointerType !== "mouse") return; clearTimeout(leaving.current); send("enter"); };
  const leave = (e: { pointerType: string }) => { if (e.pointerType !== "mouse") return; clearTimeout(leaving.current); leaving.current = setTimeout(() => send("leave"), 150); };

  return (
    <>
      <button ref={btn} type="button" className="tip-btn" aria-label={label} aria-describedby={id} aria-expanded={open}
        onClick={() => send("click")} onFocus={() => send("focus")} onBlur={() => send("blur")}
        onPointerEnter={enter} onPointerLeave={leave}>?</button>
      {createPortal(
        <span ref={pop} id={id} role="tooltip" className={"tip-pop" + (at ? " placed " + at.side : "")} hidden={!open}
          style={at ? { top: at.top, left: at.left } : undefined}
          onPointerEnter={enter} onPointerLeave={leave}>{children}</span>,
        document.body,
      )}
    </>
  );
}
