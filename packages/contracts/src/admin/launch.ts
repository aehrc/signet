/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The console's launch simulator.
 *
 * An EHR launch is otherwise impossible to exercise without an EHR: the app has
 * to be opened at its own launch URL with `iss` and a `launch` handle the
 * authorization server minted. This is the console's version of that, and it is
 * deliberately the *same* operation the EHR performs - it mints a real
 * single-use handle through the same repository - so a launch that works in the
 * simulator works from a real EHR.
 *
 * Author: John Grimes
 */

import { z } from "zod";

import { launchContextInputSchema } from "../launchContext.js";

/** Minting a launch handle from the console. */
export const launchSimulationSchema = launchContextInputSchema.extend({
  /** The app that will redeem the handle. Always bound, unlike an EHR's. */
  clientId: z.string().min(1).max(128),
});

export type LaunchSimulation = z.infer<typeof launchSimulationSchema>;
