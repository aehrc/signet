/**
 * Managing your own passkeys, in a dialog over whatever page is showing.
 *
 * A dialog rather than a page, and the reason is the same one that put it behind the
 * account menu: a passkey belongs to the person, not to a tenant, and every console
 * page below the header is about one tenant. A route for it would have to sit
 * somewhere in that hierarchy and mean something different from everything beside
 * it.
 *
 * Two things a reader has to be able to tell apart, and the whole design of the
 * states here follows from them: whether the browser is waiting for them, and why
 * something was refused. So every operation reports its own state - pending while
 * the ceremony runs, an explicit sentence for each way it can fail, and a
 * confirmation when it worked - and the sentences come from `./passkeys.js`, which is
 * tested on its own.
 *
 * Author: John Grimes
 */

import { startRegistration } from "@simplewebauthn/browser";
import { useState } from "react";

import {
  describeCeremonyFailure,
  passkeyCountLabel,
  registrationBlockedReason,
} from "./passkeys.js";
import { describeError } from "../api/errors.js";
import {
  usePasskeys,
  useRegisterPasskey,
  useRegisterPasskeyOptions,
  useRemovePasskey,
} from "../api/queries.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
} from "../components/layout.js";
import { formatInstant } from "../formatting/values.js";

import type { PasskeyView } from "../api/types.js";

/** What the dialog is doing, so only one form is open at a time. */
type Mode =
  | { readonly kind: "list" }
  | { readonly kind: "register" }
  | { readonly kind: "remove"; readonly passkey: PasskeyView };

interface PasskeyDialogProps {
  readonly open: boolean;
  readonly onClose: () => void;
}

/** The passkey management dialog. */
export function PasskeyDialog({ open, onClose }: Readonly<PasskeyDialogProps>) {
  const passkeys = usePasskeys(open);
  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [notice, setNotice] = useState<string | undefined>();

  if (!open) {
    return null;
  }

  /** Returns to the list, clearing whatever the last form was saying. */
  const backToList = (message?: string) => {
    setMode({ kind: "list" });
    setNotice(message);
  };

  return (
    <div className="modal modal-open" role="dialog" aria-modal="true">
      <div className="modal-box max-w-2xl">
        <div className="mb-1 flex items-start justify-between gap-4">
          <h2 className="text-lg font-semibold">Passkeys</h2>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            aria-label="Close"
            onClick={() => {
              backToList();
              onClose();
            }}
          >
            ✕
          </button>
        </div>
        <p className="text-base-content/70 mb-4 text-sm">
          Sign in to the console without typing your password. Passkeys belong
          to your account and work across all of your tenants.
        </p>

        {notice === undefined ? null : (
          <div className="mb-4">
            <InfoAlert>{notice}</InfoAlert>
          </div>
        )}

        {mode.kind === "register" ? (
          <RegisterForm
            count={passkeys.data?.length ?? 0}
            onCancel={() => {
              backToList();
            }}
            onRegistered={(name) => {
              backToList(`Registered "${name}".`);
            }}
          />
        ) : null}

        {mode.kind === "remove" ? (
          <RemoveForm
            passkey={mode.passkey}
            onCancel={() => {
              backToList();
            }}
            onRemoved={(name) => {
              backToList(`Removed "${name}". It will not sign you in again.`);
            }}
          />
        ) : null}

        {mode.kind === "list" ? (
          <PasskeyList
            pending={passkeys.isPending}
            failure={passkeys.error}
            passkeys={passkeys.data ?? []}
            onRegister={() => {
              setNotice(undefined);
              setMode({ kind: "register" });
            }}
            onRemove={(passkey) => {
              setNotice(undefined);
              setMode({ kind: "remove", passkey });
            }}
          />
        ) : null}
      </div>
      <button
        type="button"
        className="modal-backdrop"
        aria-label="Close"
        onClick={() => {
          backToList();
          onClose();
        }}
      />
    </div>
  );
}

interface PasskeyListProps {
  readonly pending: boolean;
  readonly failure: unknown;
  readonly passkeys: readonly PasskeyView[];
  readonly onRegister: () => void;
  readonly onRemove: (passkey: PasskeyView) => void;
}

/** The registered passkeys, or an explanation of what one is. */
function PasskeyList({
  pending,
  failure,
  passkeys,
  onRegister,
  onRemove,
}: Readonly<PasskeyListProps>) {
  if (pending) {
    return <Loading label="Reading your passkeys…" />;
  }
  if (failure !== null && failure !== undefined) {
    // Not a ceremony: reading the list raises no browser prompt, so the only
    // thing that can arrive here is the server's own refusal.
    return <ErrorAlert message={describeError(failure)} />;
  }

  const blocked = registrationBlockedReason(passkeys.length);
  const register = (
    <button
      type="button"
      className="btn btn-primary btn-sm"
      disabled={blocked !== undefined}
      onClick={onRegister}
    >
      Register a passkey
    </button>
  );

  if (passkeys.length === 0) {
    return (
      <EmptyState
        title="No passkeys yet"
        description="A passkey is a credential your device holds - a fingerprint, a face or a PIN unlocks it, and nothing is typed. It cannot be phished, because it only works on this site."
        action={register}
      />
    );
  }

  return (
    <>
      <div className="overflow-x-auto">
        <table className="table table-sm">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {passkeys.map((passkey) => (
              <tr key={passkey.id}>
                <td>{passkey.name}</td>
                <td>{formatInstant(passkey.createdAt)}</td>
                <td>{formatInstant(passkey.lastUsedAt)}</td>
                <td className="text-right">
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs"
                    aria-label={`Remove ${passkey.name}`}
                    onClick={() => {
                      onRemove(passkey);
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        {register}
        <span className="text-base-content/60 text-xs">
          {passkeyCountLabel(passkeys.length)}
        </span>
      </div>
      {blocked === undefined ? null : (
        <p className="text-base-content/70 mt-2 text-xs">{blocked}</p>
      )}
    </>
  );
}

interface RegisterFormProps {
  readonly count: number;
  readonly onCancel: () => void;
  readonly onRegistered: (name: string) => void;
}

/**
 * Confirming the password, naming the passkey, and running the ceremony.
 *
 * Three requests in one submission, and the order matters: the password is checked
 * before the browser prompt is raised, so a mistyped one is refused without spending
 * somebody's fingerprint on a request that was going to fail.
 */
function RegisterForm({
  count,
  onCancel,
  onRegistered,
}: Readonly<RegisterFormProps>) {
  const options = useRegisterPasskeyOptions();
  const register = useRegisterPasskey();
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [failure, setFailure] = useState<string | undefined>();
  const [waiting, setWaiting] = useState(false);

  const pending = options.isPending || register.isPending || waiting;

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        setFailure(undefined);
        options.mutate(password, {
          onSuccess: (creation) => {
            setWaiting(true);
            startRegistration({ optionsJSON: creation })
              .then((response) => {
                register.mutate(
                  { name: name.trim() === "" ? null : name.trim(), response },
                  {
                    onSuccess: (passkey) => {
                      setWaiting(false);
                      onRegistered(passkey.name);
                    },
                    onError: (error) => {
                      setWaiting(false);
                      setFailure(
                        describeCeremonyFailure(error, "registration"),
                      );
                    },
                  },
                );
              })
              .catch((error: unknown) => {
                setWaiting(false);
                setFailure(describeCeremonyFailure(error, "registration"));
              });
          },
          onError: (error) => {
            setFailure(describeCeremonyFailure(error, "registration"));
          },
        });
      }}
    >
      <h3 className="font-medium">Register a passkey</h3>
      <p className="text-base-content/70 text-sm">
        Confirm your password, then your browser will ask you to create the
        passkey.
      </p>

      <TextField
        label="Current password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={pending}
        required
      />
      <TextField
        label="Passkey name"
        value={name}
        onChange={setName}
        hint={`Something you will recognise later. Left blank, it is named "Passkey ${String(count + 1)}".`}
        disabled={pending}
      />

      {waiting ? <InfoAlert>Waiting for your browser…</InfoAlert> : null}
      {failure === undefined ? null : <ErrorAlert message={failure} />}

      <div className="mt-2 flex items-center gap-3">
        <SubmitButton pending={pending}>Create passkey</SubmitButton>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={pending}
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

interface RemoveFormProps {
  readonly passkey: PasskeyView;
  readonly onCancel: () => void;
  readonly onRemoved: (name: string) => void;
}

/** Confirming the password before a passkey stops working. */
function RemoveForm({
  passkey,
  onCancel,
  onRemoved,
}: Readonly<RemoveFormProps>) {
  const removal = useRemovePasskey();
  const [password, setPassword] = useState("");
  const [failure, setFailure] = useState<string | undefined>();

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        setFailure(undefined);
        removal.mutate(
          { passkeyId: passkey.id, password },
          {
            onSuccess: () => {
              onRemoved(passkey.name);
            },
            onError: (error) => {
              // Removal raises no browser prompt either: a wrong password and a
              // passkey that is already gone are the only ways this fails, and
              // the server words both.
              setFailure(describeError(error));
            },
          },
        );
      }}
    >
      <h3 className="font-medium">Remove &ldquo;{passkey.name}&rdquo;</h3>
      <p className="text-base-content/70 text-sm">
        It stops working immediately. Your password still signs you in, so
        removing your last passkey cannot lock you out.
      </p>

      <TextField
        label="Current password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={removal.isPending}
        required
      />

      {failure === undefined ? null : <ErrorAlert message={failure} />}

      <div className="mt-2 flex items-center gap-3">
        <SubmitButton pending={removal.isPending}>Remove passkey</SubmitButton>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={removal.isPending}
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
