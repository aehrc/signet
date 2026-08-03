import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app.js";

import "./styles.css";

const container = document.querySelector("#root");
if (!container) {
  throw new Error("Root container #root is missing from the document");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
