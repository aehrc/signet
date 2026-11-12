/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the invitation page sends to `{iss}/invitation/details` and
 * `{iss}/invitation/accept`.
 *
 * The token travels in the body rather than the URL, so it stays out of access logs.
 * The password carries the same bounds as an administrator setting one.
 *
 * Author: John Grimes
 */

import { z } from "zod";

import { endUserPasswordSchema } from "./admin/users.js";

/** Looking up the account an invitation link is for. */
export const invitationDetailsSchema = z.object({
  token: z.string().min(1).max(256),
});

/** Choosing the password through an invitation link. */
export const invitationAcceptSchema = invitationDetailsSchema.extend(
  endUserPasswordSchema.shape,
);

export type InvitationDetails = z.infer<typeof invitationDetailsSchema>;
export type InvitationAccept = z.infer<typeof invitationAcceptSchema>;
