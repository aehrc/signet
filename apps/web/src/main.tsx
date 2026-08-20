/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

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
