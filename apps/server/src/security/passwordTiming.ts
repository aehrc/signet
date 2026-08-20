/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Making a rejection cost the same whether or not the account exists.
 *
 * Argon2id verification dominates the cost of a sign-in, so a path that skips it
 * when the username is unknown answers measurably faster - which turns user
 * enumeration into a timing measurement rather than a guess. Both sign-in paths
 * (the console's and the end user's) therefore verify the presented password
 * against this hash when they found no account, and only then refuse.
 *
 * Shared rather than duplicated so the two paths cannot drift into having
 * different costs, which would reintroduce the difference between them.
 *
 * Author: John Grimes
 */

/**
 * An Argon2id hash that no password can match.
 *
 * The salt and digest are fixed nonsense with the parameters
 * {@link hashPassword} uses, so verifying against it costs what verifying a real
 * stored hash costs. Nothing ever verifies against it successfully.
 */
export const UNMATCHABLE_PASSWORD_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$c2lnbmV0LW5vLXN1Y2gtdXNlcg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
