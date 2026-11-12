/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * An end user's email address and whether it is verified.
 *
 * Shared by the add-user form and the user detail page, which both offer it on an
 * OAuth endpoint only - the `email` scope that releases it exists only there. The
 * verified flag is its own control rather than inferred, because Signet sends no
 * verification mail: an operator who has checked the address says so, and an app
 * reading `email_verified` is told exactly that and nothing more.
 *
 * Author: John Grimes
 */

import { CheckboxField, TextField } from "../components/fields.js";

interface EmailFieldsProps {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly onEmail: (email: string) => void;
  readonly onEmailVerified: (verified: boolean) => void;
  /** The API's refusals, by field. */
  readonly issues: Readonly<Record<string, string>>;
  readonly disabled?: boolean;
}

/** The email address and its verified flag. */
export function EmailFields({
  email,
  emailVerified,
  onEmail,
  onEmailVerified,
  issues,
  disabled,
}: Readonly<EmailFieldsProps>) {
  return (
    <>
      <TextField
        label="Email"
        type="email"
        value={email}
        onChange={onEmail}
        error={issues["email"]}
        hint="Released to apps granted the email scope. Clearing this removes it."
        disabled={disabled ?? false}
      />
      <CheckboxField
        label="Email address is verified"
        checked={emailVerified}
        onChange={onEmailVerified}
        hint="Released as email_verified. Signet sends no verification mail, so tick this only once you have confirmed the address belongs to this person."
        disabled={disabled ?? false}
      />
    </>
  );
}
