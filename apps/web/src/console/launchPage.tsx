/**
 * The launch simulator.
 *
 * An EHR launch is otherwise impossible to exercise without an EHR: the app has to be
 * opened at its own launch URL with `iss` and a `launch` handle that the authorization
 * server minted. This mints a real handle through the same repository the EHR endpoint
 * uses, with the same five-minute lifetime and the same single-use semantics - so a
 * launch that works here works from a real EHR, because it is the same operation.
 *
 * The handle is always bound to the client being launched. An unbound handle is
 * redeemable by whichever app presents it first, which is only acceptable when the EHR
 * genuinely does not know which app is about to open - and the console always knows.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useClients, useSimulateLaunch } from "../api/queries.js";
import { SubmitButton, TextField } from "../components/fields.js";
import { SelectField } from "../components/fields.js";
import {
  CopyableValue,
  DetailList,
  DetailRow,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { formatDuration } from "../formatting/values.js";
import { withoutBlanks } from "../forms/lists.js";

/** The launch simulator page. */
export function LaunchPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const clients = useClients(tenant, endpointSlug);
  const launch = useSimulateLaunch(tenant, endpointSlug);

  const [clientId, setClientId] = useState("");
  const [patient, setPatient] = useState("");
  const [encounter, setEncounter] = useState("");
  const [intent, setIntent] = useState("");

  const mayLaunch = roleAllows(role, "developer");
  // Only clients with a launch URI can be opened, since the point is to navigate to
  // one. A client without one can still be authorized standalone.
  const launchable = (clients.data ?? []).filter(
    (client) => client.launchUri !== null && client.status === "active",
  );
  const chosen = clientId === "" ? launchable[0]?.clientId : clientId;

  return (
    <>
      <PageHeader
        title="Launch simulator"
        description="Mint a launch handle and open an app with it, exactly as an EHR would. The handle is single-use and lasts five minutes."
      />

      {endpoint.capabilities["supportsEhrLaunch"] === false ? (
        <InfoAlert>
          This endpoint does not support the EHR launch, so a handle minted here
          would never be redeemable. Enable it under the endpoint&apos;s
          capabilities first.
        </InfoAlert>
      ) : null}

      <Panel title="Launch an app">
        {clients.isPending ? <Loading /> : null}
        {clients.isError ? (
          <ErrorAlert message={describeError(clients.error)} />
        ) : null}

        {clients.data !== undefined && launchable.length === 0 ? (
          <InfoAlert>
            No active client on this endpoint has a launch URI. An EHR launch
            opens the app at its own URL, so a client needs one to be launchable
            - add it under Clients.
          </InfoAlert>
        ) : null}

        {launchable.length === 0 ? null : (
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (chosen === undefined) {
                return;
              }
              launch.mutate({
                clientId: chosen,
                ...withoutBlanks({ patient, encounter, intent }),
              });
            }}
          >
            <SelectField
              label="App"
              value={chosen ?? ""}
              onChange={setClientId}
              options={launchable.map((client) => ({
                value: client.clientId,
                label: client.name,
              }))}
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <TextField
                label="Patient"
                value={patient}
                onChange={setPatient}
                hint="The FHIR id the app should be opened for."
              />
              <TextField
                label="Encounter"
                value={encounter}
                onChange={setEncounter}
              />
            </div>
            <TextField
              label="Intent"
              value={intent}
              onChange={setIntent}
              hint="Free text the app may use to decide which of its screens to open."
            />

            {launch.isError ? (
              <ErrorAlert message={describeError(launch.error)} />
            ) : null}

            <div>
              <SubmitButton pending={launch.isPending} disabled={!mayLaunch}>
                Mint a launch
              </SubmitButton>
            </div>
          </form>
        )}
      </Panel>

      {launch.data === undefined ? null : (
        <Panel
          title="Launch"
          description={`Single-use, and valid for ${formatDuration(launch.data.expiresIn)}.`}
          actions={
            launch.data.launchUrl === null ? undefined : (
              <a
                className="btn btn-primary btn-sm"
                href={launch.data.launchUrl}
                target="_blank"
                rel="noreferrer"
              >
                Open the app
              </a>
            )
          }
        >
          <DetailList>
            <DetailRow label="iss">
              <CopyableValue value={launch.data.iss} label="issuer" />
            </DetailRow>
            <DetailRow label="launch">
              <CopyableValue value={launch.data.launch} label="launch handle" />
            </DetailRow>
            {launch.data.launchUrl === null ? null : (
              <DetailRow label="Launch URL">
                <CopyableValue
                  value={launch.data.launchUrl}
                  label="launch URL"
                />
              </DetailRow>
            )}
          </DetailList>
        </Panel>
      )}
    </>
  );
}
