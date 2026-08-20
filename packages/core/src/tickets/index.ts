/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

export {
  capExchangedTokenLifetime,
  intersectTicketScopes,
  type ExchangedTokenCeilings,
  type TicketScopeRefusal,
  type TicketScopeResult,
  type TicketScopeSides,
} from "./intersect.js";
export {
  ACCESS_TOKEN_TYPE,
  JWT_SUBJECT_TOKEN_TYPE,
  PERMITTED_TICKET_ALGORITHMS,
  TICKET_CLOCK_TOLERANCE_SECONDS,
  TOKEN_EXCHANGE_GRANT_TYPE,
  validatePermissionTicket,
  type TicketCheck,
  type TicketRefusal,
  type TicketSubject,
  type TicketValidation,
  type ValidatedTicket,
} from "./validate.js";
