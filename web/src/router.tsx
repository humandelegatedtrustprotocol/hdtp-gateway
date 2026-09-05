// A deliberately tiny history router. The portal has a dozen flat views; a
// routing library would be the largest dependency in the bundle for the sake
// of features none of them use.
import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode, MouseEvent } from "react";

const PathCtx = createContext<string>("/");

export function navigate(to: string) {
  history.pushState(null, "", to);
  dispatchEvent(new PopStateEvent("popstate"));
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [path, setPath] = useState(location.pathname);
  useEffect(() => {
    const on = () => setPath(location.pathname);
    addEventListener("popstate", on);
    return () => removeEventListener("popstate", on);
  }, []);
  return <PathCtx.Provider value={path}>{children}</PathCtx.Provider>;
}

export function usePath(): string {
  return useContext(PathCtx);
}

export function Link({ to, className, title, children, onClick: after, ...rest }: { to: string; className?: string; title?: string; children: ReactNode; onClick?: (e: MouseEvent) => void; role?: string; "aria-label"?: string; "aria-pressed"?: boolean }) {
  const onClick = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return; // let the browser open tabs
    after?.(e);
    if (e.defaultPrevented) return; // the handler vetoed (a confirm was refused)
    e.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} className={className} title={title} onClick={onClick} {...rest}>
      {children}
    </a>
  );
}
