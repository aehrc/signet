/**
 * Signing in to the console.
 *
 * The second factor is asked for on a second pass rather than up front, because
 * whether an account has enrolled one is not something the server will say before
 * the password has been accepted. So the form posts what it has; when the API answers
 * `totpRequired`, the code field appears and the form posts again.
 *
 * Every other refusal shows the server's own message, which is deliberately the same
 * sentence for an unknown account, a wrong password and a disabled one.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { useNavigate } from "react-router";

import { CONSOLE_BASE } from "./routes.js";
import { ApiError } from "../api/errors.js";
import { useSignIn } from "../api/queries.js";
import { CentredShell } from "../components/appShell.js";
import { SubmitButton, TextField } from "../components/fields.js";
import { ErrorAlert } from "../components/layout.js";

/**
 * Whether a refusal is the server asking for a verification code.
 *
 * The flag is on the body rather than being inferred from the message, so the
 * console never has to match on prose.
 *
 * @param error - The value the mutation threw.
 */
function needsSecondFactor(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.status === 401 &&
    error.flag("totpRequired")
  );
}

/** The console's sign-in page. */
export function SignInPage() {
  const signIn = useSignIn();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [wantsTotp, setWantsTotp] = useState(false);

  const failure = signIn.error;

  return (
    <CentredShell
      title="Sign in"
      subtitle="Signet is the authorization server in front of your FHIR server. Sign in to manage its endpoints."
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          signIn.mutate(
            {
              email,
              password,
              ...(totp.length === 0 ? {} : { totp }),
            },
            {
              onSuccess: () => {
                // The console layout decides where to land: the caller's only
                // tenant, or the chooser when they belong to several. Deciding it
                // here would duplicate that rule in the one place it must not
                // differ.
                void navigate(CONSOLE_BASE, { replace: true });
              },
              onError: (error) => {
                if (needsSecondFactor(error)) {
                  setWantsTotp(true);
                }
              },
            },
          );
        }}
      >
        <TextField
          label="Email"
          type="email"
          value={email}
          onChange={setEmail}
          autoComplete="username"
          required
        />
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          required
        />
        {wantsTotp ? (
          <TextField
            label="Verification code"
            value={totp}
            onChange={setTotp}
            autoComplete="one-time-code"
            hint="Six digits from your authenticator app."
            required
          />
        ) : null}

        {failure !== null && !needsSecondFactor(failure) ? (
          <ErrorAlert
            message={
              failure instanceof ApiError
                ? failure.message
                : "Could not reach the server."
            }
          />
        ) : null}

        <div className="mt-2">
          <SubmitButton pending={signIn.isPending}>Sign in</SubmitButton>
        </div>
      </form>
    </CentredShell>
  );
}
