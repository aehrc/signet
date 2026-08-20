/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The three pages an authorization passes through: sign in, choose, consent.
 *
 * Each is a client of the interaction API and holds no state of its own beyond what is
 * being typed. That is deliberate and it is what makes the flow safe: the scopes, the
 * redirect URI and the PKCE challenge all live in the `authorization_sessions` row, and
 * every response says which step the session is *actually* on. So a page cannot advance
 * the flow by claiming to - it posts, and renders whatever it is told next.
 *
 * The session identifier is in the query string. It is not a credential: reading a
 * session tells the caller what the app asked for, which the app already knows, and
 * advancing one needs a credential the identifier does not contain.
 *
 * These pages are the only part of Signet whose audience is a patient or a clinician
 * rather than a developer, so they carry no console chrome and every scope is translated
 * into a sentence - see `./scopeDescriptions.js`.
 *
 * They are also the pages most likely to be read on a phone: an authorization redirect
 * arrives on whatever device the app is running on. The `max-sm:` classes are that
 * half of the layout - the two consent decisions stack full-width rather than sitting
 * side by side as a pair of 70px buttons, the scope descriptions read at 16px, and
 * every identifier is allowed to break rather than widen the card.
 *
 * Author: John Grimes
 */

import { useEffect, useState } from "react";
import {
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router";

import { issuerBase } from "./api.js";
import { ChoiceList } from "./choiceList.js";
import { useAdvanceInteraction, useInteractionState } from "./queries.js";
import { describeScopes, includesWrites } from "./scopeDescriptions.js";
import { ScopeMarker } from "./scopeMarker.js";
import { nextStepPath } from "./steps.js";
import { describeError } from "../api/errors.js";
import { CentredShell } from "../components/appShell.js";
import { SubmitButton, TextField } from "../components/fields.js";
import { ErrorAlert, InfoAlert, Loading } from "../components/layout.js";
import { withoutBlanks } from "../forms/lists.js";

import type { InteractionState } from "./api.js";
import type { ReactNode } from "react";

/** What every interaction page needs from the URL. */
interface InteractionRoute {
  readonly tenant: string;
  readonly endpoint: string;
  readonly session: string;
}

/** Reads the endpoint and session from the URL. */
function useInteractionRoute(): InteractionRoute | undefined {
  const { tenant, endpoint } = useParams<{
    tenant: string;
    endpoint: string;
  }>();
  const [search] = useSearchParams();
  const session = search.get("session");

  if (tenant === undefined || endpoint === undefined || session === null) {
    return undefined;
  }
  return { tenant, endpoint, session };
}

/**
 * Keeps the browser on the page the server says the flow is on.
 *
 * Two destinations. A `complete` or `denied` step carries a redirect out of Signet
 * altogether - to the app, with a code or with `access_denied` - and that is a full
 * navigation. Any other step belongs on one of the three pages, and moving between them
 * is a client-side navigation carrying the session identifier, so a reload lands where
 * the flow actually is.
 *
 * A legitimate effect either way: it synchronises an external system - the browser's
 * location - with what the server said, and sets no React state.
 *
 * @param state - The interaction state, once it has loaded.
 * @param sessionId - The authorization session's identifier.
 */
function useFollowFlow(
  state: InteractionState | undefined,
  sessionId: string,
): void {
  const location = useLocation();
  const navigate = useNavigate();
  const redirectTo = state?.redirectTo;
  const step = state?.step;

  useEffect(() => {
    if (redirectTo !== undefined) {
      globalThis.location.assign(redirectTo);
      return;
    }
    if (step === undefined) {
      return;
    }
    const target = nextStepPath(location.pathname, step, sessionId);
    if (target !== undefined) {
      void navigate(target, { replace: true });
    }
  }, [redirectTo, step, location.pathname, sessionId, navigate]);
}

/**
 * Everything an interaction page needs: the state, and the way to advance it.
 *
 * One hook rather than three call sites repeating the same four arguments - and the
 * empty-string fallbacks are safe because a page with no route renders
 * {@link MissingSession} before any of this is used.
 */
function useInteractionPage(route: InteractionRoute | undefined) {
  const interaction = useInteractionState(
    route?.tenant ?? "",
    route?.endpoint ?? "",
    route?.session ?? "",
  );
  const advance = useAdvanceInteraction(
    route?.tenant ?? "",
    route?.endpoint ?? "",
    route?.session ?? "",
  );
  useFollowFlow(interaction.data, route?.session ?? "");
  return { interaction, advance } as const;
}

/**
 * The shell's props for a page, derived from what it has loaded.
 *
 * All three pages frame themselves the same way - the state, the failure that stops it
 * rendering, a title, and a subtitle naming the app - and the only difference is the
 * wording. Deriving it means the "is this failure fatal?" decision is made once.
 *
 * @param state - The interaction state, once it has loaded.
 * @param error - The query's failure, if it failed.
 * @param title - The page's heading.
 * @param subtitle - A sentence about the asking app, given its name.
 */
function shellPropsFor(
  state: InteractionState | undefined,
  error: unknown,
  title: string,
  subtitle: (clientName: string) => string,
): Omit<ShellProps, "children"> {
  return {
    state,
    // Only fatal before anything has loaded: once a step is on screen, a failed post
    // belongs inside the page beside the form that caused it.
    fatal: state === undefined ? error : undefined,
    title,
    subtitle: state === undefined ? undefined : subtitle(state.client.name),
  };
}

interface ShellProps {
  readonly state: InteractionState | undefined;
  /** A failure that stops the page rendering, rather than one to show inside it. */
  readonly fatal: unknown;
  readonly title: string;
  readonly subtitle?: string | undefined;
  readonly children: ReactNode;
}

/** The frame the three pages share. */
function InteractionShell({
  state,
  fatal,
  title,
  subtitle,
  children,
}: Readonly<ShellProps>) {
  if (fatal !== undefined && fatal !== null) {
    return (
      <CentredShell title="This request cannot continue">
        <ErrorAlert message={describeError(fatal)} />
        <p className="text-base-content/70 text-sm max-sm:text-base">
          Close this window and start again from the app.
        </p>
      </CentredShell>
    );
  }
  if (state === undefined) {
    return (
      <CentredShell title={title}>
        <Loading />
      </CentredShell>
    );
  }
  return (
    <CentredShell
      title={title}
      subtitle={subtitle}
      footer={
        <span>
          {state.client.name} is asking. Signet is checking that you agree.
        </span>
      }
    >
      {children}
    </CentredShell>
  );
}

/**
 * The way out of the login page when authentication happens somewhere else.
 *
 * A plain link rather than a fetch, because the round trip is a browser
 * navigation: the provider needs to see the person, set its own cookies, and
 * redirect them back. A `fetch` would follow the redirect in the background and
 * hand back a page the person never got to interact with.
 *
 * @param route - The props.
 * @param route.route - The endpoint and session, from the URL.
 * @param route.name - What the operator called the provider, if anything.
 */
function FederationPrompt({
  route,
  name,
}: Readonly<{ route: InteractionRoute; name: string | null }>) {
  const target = `${issuerBase(route.tenant, route.endpoint)}/federation/start?session=${encodeURIComponent(route.session)}`;
  return (
    <div className="flex flex-col gap-3">
      <InfoAlert>
        This endpoint signs you in through
        {name === null ? " another identity provider" : ` ${name}`}.
      </InfoAlert>
      <div>
        <a
          className="btn btn-primary max-sm:min-h-11 max-sm:w-full"
          href={target}
        >
          {name === null ? "Continue to sign in" : `Continue with ${name}`}
        </a>
      </div>
    </div>
  );
}

/** The page `/authorize` sends the browser to. */
export function LoginPage() {
  const route = useInteractionRoute();
  const { interaction, advance } = useInteractionPage(route);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  if (route === undefined) {
    return <MissingSession />;
  }

  const state = interaction.data;

  return (
    <InteractionShell
      {...shellPropsFor(
        state,
        interaction.error,
        "Sign in",
        (clientName) => `${clientName} would like you to sign in.`,
      )}
    >
      {advance.error === null ? null : (
        <ErrorAlert message={describeError(advance.error)} />
      )}

      {state?.authMode === "oidc" ? (
        <FederationPrompt route={route} name={state.federation?.name ?? null} />
      ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            advance.mutate({
              kind: "login",
              credentials: { username, password },
            });
          }}
        >
          <TextField
            label="Username"
            value={username}
            onChange={setUsername}
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
          <div>
            <SubmitButton pending={advance.isPending}>Sign in</SubmitButton>
          </div>
        </form>
      )}

      {state === undefined ? null : (
        <ChoiceList
          choices={state.personas.map((persona) => ({
            value: persona.id,
            label: persona.displayName,
            detail: persona.fhirUser,
          }))}
          disabled={advance.isPending}
          onChoose={(personaId) => {
            advance.mutate({ kind: "login", credentials: { personaId } });
          }}
        >
          <div className="border-base-300 border-t pt-3">
            <p className="mb-1 text-sm font-medium max-sm:text-base">
              Or continue as
            </p>
            <p className="text-base-content/60 mb-2 text-xs max-sm:text-base">
              These are demonstration accounts. This endpoint is not marked
              production, so they need no password.
            </p>
          </div>
        </ChoiceList>
      )}
    </InteractionShell>
  );
}

/** The patient picker, for a launch whose context nobody has supplied. */
export function PickerPage() {
  const route = useInteractionRoute();
  const { interaction, advance } = useInteractionPage(route);
  const [patient, setPatient] = useState("");
  const [encounter, setEncounter] = useState("");

  if (route === undefined) {
    return <MissingSession />;
  }

  const state = interaction.data;

  return (
    <InteractionShell
      {...shellPropsFor(
        state,
        interaction.error,
        "Choose a record",
        (clientName) => `${clientName} needs to know which record it is about.`,
      )}
    >
      {advance.error === null ? null : (
        <ErrorAlert message={describeError(advance.error)} />
      )}

      {state === undefined ? null : (
        <ChoiceList
          choices={state.patients.map((candidate) => ({
            value: candidate,
            label: candidate,
          }))}
          disabled={advance.isPending}
          onChoose={(patientId) => {
            advance.mutate({
              kind: "context",
              chosen: { patient: patientId },
            });
          }}
        />
      )}

      {state?.allowsFreeContextSelection === true ? (
        <form
          className="border-base-300 flex flex-col gap-3 border-t pt-3"
          onSubmit={(event) => {
            event.preventDefault();
            advance.mutate({
              kind: "context",
              chosen: withoutBlanks({ patient, encounter }),
            });
          }}
        >
          <TextField
            label="Patient identifier"
            value={patient}
            onChange={setPatient}
            hint="This endpoint is not marked production, so any identifier may be entered."
          />
          {state.requirements.encounter ? (
            <TextField
              label="Encounter identifier"
              value={encounter}
              onChange={setEncounter}
            />
          ) : null}
          <div>
            <SubmitButton pending={advance.isPending}>Continue</SubmitButton>
          </div>
        </form>
      ) : null}

      {state !== undefined &&
      state.patients.length === 0 &&
      !state.allowsFreeContextSelection ? (
        <InfoAlert>
          Your account has no records associated with it, so this app cannot be
          opened. Ask whoever administers this system to associate one.
        </InfoAlert>
      ) : null}
    </InteractionShell>
  );
}

/** The consent screen. */
export function ConsentPage() {
  const route = useInteractionRoute();
  const { interaction, advance } = useInteractionPage(route);

  if (route === undefined) {
    return <MissingSession />;
  }

  const state = interaction.data;
  const scopes =
    state === undefined ? [] : describeScopes(state.requestedScopes);
  const patient =
    state?.resolvedContext === null || state?.resolvedContext === undefined
      ? undefined
      : (state.resolvedContext["patient"] as string | undefined);

  return (
    <InteractionShell
      {...shellPropsFor(
        state,
        interaction.error,
        "Allow access?",
        (clientName) => `${clientName} is asking for the following.`,
      )}
    >
      {advance.error === null ? null : (
        <ErrorAlert message={describeError(advance.error)} />
      )}

      {patient === undefined ? null : (
        <p className="text-base-content/70 text-sm break-words max-sm:text-base">
          For the record{" "}
          <code className="bg-base-200 rounded-field px-1 font-mono text-xs break-words">
            {patient}
          </code>
          .
        </p>
      )}

      <ul className="flex flex-col gap-2">
        {scopes.map((described) => (
          <li
            key={described.scope}
            className="flex items-start gap-2 text-sm max-sm:text-base"
          >
            {/* The marker centres on the first line of the description, so it
                moves down with the taller text below `sm`. */}
            <ScopeMarker
              writes={described.writes}
              className="mt-0.5 max-sm:mt-1.5"
            />
            <span className="min-w-0">
              {described.description}
              {/*
                The technical scope sits beside the sentence on a desktop and on
                its own line below `sm`, as the wireframe has it. Breaking it
                mid-word instead would split `launch/patient` across two lines,
                which is harder to read than the line it costs.
              */}
              <code className="text-base-content/50 ml-2 font-mono text-xs break-words max-sm:ml-0 max-sm:block">
                {described.scope}
              </code>
            </span>
          </li>
        ))}
      </ul>

      {state !== undefined && includesWrites(state.requestedScopes) ? (
        <InfoAlert>
          Some of this permits the app to add to, change or delete information
          in your record - not only to read it.
        </InfoAlert>
      ) : null}

      {/*
        The two decisions stack full-width below `sm`. Side by side they are 71px
        and 69px wide on a 360px viewport - under the 44px minimum in height and
        small enough that a thumb aimed at "Allow" can land on "Deny", which is
        the one misfire on this screen that matters.
      */}
      <div className="flex gap-2 max-sm:flex-col">
        <button
          type="button"
          className="btn btn-primary max-sm:min-h-11 max-sm:w-full"
          disabled={advance.isPending}
          onClick={() => {
            advance.mutate({ kind: "consent", approve: true });
          }}
        >
          Allow
        </button>
        <button
          type="button"
          className="btn btn-ghost max-sm:min-h-11 max-sm:w-full"
          disabled={advance.isPending}
          onClick={() => {
            advance.mutate({ kind: "consent", approve: false });
          }}
        >
          Deny
        </button>
      </div>
    </InteractionShell>
  );
}

/** What a page reached without a session identifier shows. */
function MissingSession() {
  return (
    <CentredShell title="Nothing to authorize">
      <p className="text-base-content/70 text-sm max-sm:text-base">
        This page is opened by an app as part of signing in. Start from the app
        rather than from here.
      </p>
    </CentredShell>
  );
}
