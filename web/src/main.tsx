import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
// The brand (hdtp-web-kit's palette, type and motion) first, then the layout built on it.
import "./brand.css";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
