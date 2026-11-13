-- Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
-- (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

-- Plain text an operator shows on an endpoint's end-user sign-in page, such as who
-- to contact for an account. Null means no message.
ALTER TABLE "endpoints" ADD COLUMN "login_message" text;
