/**
 * The policy editor.
 *
 * One document, two modes, one simulator. The document lives in this component's state
 * and is the source of truth; the builder edits it structurally, the code view edits text
 * that parses back to it, and switching between them is therefore lossless by
 * construction rather than by a conversion step.
 *
 * Saving creates a new version rather than editing one. That is what makes a rollback a
 * publish - republish the version before the mistake - and it is why the save panel shows
 * a diff against what is currently live: publishing changes what every token from this
 * endpoint carries, and a confirmation dialogue that said "are you sure?" would be
 * asking about something the operator cannot see.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { CodeEditor } from "./codeEditor.js";
import { formatPolicy, parsePolicy, policiesDiffer } from "./document.js";
import { PolicyDiff } from "./policyDiff.js";
import { RuleBuilder } from "./ruleBuilder.js";
import { withRuleIds } from "./rules.js";
import { SimulatePanel } from "./simulatePanel.js";
import { describeError } from "../api/errors.js";
import {
  useCreatePolicy,
  usePolicies,
  usePresets,
  usePublishPolicy,
} from "../api/queries.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { DataTable, StatusBadge } from "../components/table.js";
import { roleAllows, useEndpointContext } from "../console/useConsole.js";
import { formatInstant } from "../formatting/values.js";

import type { DocumentIssue } from "./document.js";
import type { PolicyView } from "../api/types.js";
import type { Column } from "../components/table.js";
import type { PolicyDocument } from "@signet/core";

/** Which mode the editor is in. */
type Mode = "builder" | "code";

/** The policy editor page. */
export function PolicyPage() {
  const { tenant, endpointSlug, role } = useEndpointContext();
  const versions = usePolicies(tenant, endpointSlug);

  if (versions.isPending) {
    return <Loading label="Loading the policy…" />;
  }
  if (versions.isError) {
    return <ErrorAlert message={describeError(versions.error)} />;
  }

  const published = versions.data?.find((version) => version.published);
  const starting = published ?? versions.data?.[0];

  return (
    <PolicyEditor
      // Remounted when the live version changes, so a save resets the editor to what
      // is now published rather than leaving the previous edit in place.
      key={`${String(starting?.version ?? 0)}-${String(published?.version ?? 0)}`}
      tenant={tenant}
      endpointSlug={endpointSlug}
      versions={versions.data ?? []}
      starting={starting}
      mayEdit={roleAllows(role, "admin")}
    />
  );
}

interface PolicyEditorProps {
  readonly tenant: string;
  readonly endpointSlug: string;
  readonly versions: readonly PolicyView[];
  readonly starting: PolicyView | undefined;
  readonly mayEdit: boolean;
}

/** The editor proper, once a starting version is known. */
function PolicyEditor({
  tenant,
  endpointSlug,
  versions,
  starting,
  mayEdit,
}: Readonly<PolicyEditorProps>) {
  const create = useCreatePolicy(tenant, endpointSlug);
  const publish = usePublishPolicy(tenant, endpointSlug);
  const presets = usePresets();

  const loaded = startingDocument(starting);
  const [mode, setMode] = useState<Mode>("builder");
  const [document, setDocument] = useState<PolicyDocument | undefined>(loaded);
  const [text, setText] = useState(
    loaded === undefined ? "" : formatPolicy(loaded),
  );
  const [issues, setIssues] = useState<readonly DocumentIssue[]>([]);
  const [note, setNote] = useState("");

  const changed =
    document !== undefined &&
    loaded !== undefined &&
    policiesDiffer(loaded, document);

  /** Applies a structural edit from the builder, keeping the text in step. */
  const applyDocument = (next: PolicyDocument) => {
    setDocument(next);
    setText(formatPolicy(next));
    setIssues([]);
  };

  /** Applies a textual edit, keeping the document in step when it parses. */
  const applyText = (next: string) => {
    setText(next);
    const parsed = parsePolicy(next);
    if (parsed.ok) {
      setDocument(parsed.document);
      setIssues([]);
    } else {
      // The document is left as it was, so the simulator and the builder keep
      // showing the last good state rather than emptying while a rule is typed.
      setDocument(undefined);
      setIssues(parsed.issues);
    }
  };

  return (
    <>
      <PageHeader
        title="Policy"
        description="What this endpoint grants, and what its tokens carry. Versions are immutable: editing creates a new one, and publishing points the endpoint at it."
        actions={
          <>
            <DraftStatus changed={changed} issueCount={issues.length} />
            <div role="tablist" className="tabs tabs-box tabs-sm">
              <button
                type="button"
                role="tab"
                className={`tab ${mode === "builder" ? "tab-active" : ""}`}
                onClick={() => {
                  setMode("builder");
                }}
              >
                Builder
              </button>
              <button
                type="button"
                role="tab"
                className={`tab ${mode === "code" ? "tab-active" : ""}`}
                onClick={() => {
                  setMode("code");
                }}
              >
                Code
              </button>
            </div>
          </>
        }
      />

      {starting === undefined ? (
        <InfoAlert>
          This endpoint has no policy version. Until one is published it cannot
          issue a token: the token endpoint refuses rather than inventing a
          permissive default.
        </InfoAlert>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div>
          {mode === "code" ? (
            <Panel
              title="Document"
              description="The policy as JSON - the form it takes in the database and over the API. Problems are listed beneath and do not stop you typing."
            >
              <CodeEditor
                value={text}
                onChange={applyText}
                issues={issues}
                disabled={!mayEdit}
              />
            </Panel>
          ) : (
            <BuilderPane
              document={document}
              onChange={applyDocument}
              disabled={!mayEdit}
            />
          )}

          {mayEdit ? (
            <Panel
              id="save-panel"
              title="Save"
              description="Creates a new version. Publishing it makes it the one every token is issued under."
            >
              {changed && document !== undefined && starting !== undefined ? (
                <PolicyDiff
                  before={formatPolicy(startingDocument(starting) ?? document)}
                  after={formatPolicy(document)}
                />
              ) : (
                <p className="text-base-content/70 text-sm">
                  {issues.length > 0
                    ? "Fix the problems above before saving."
                    : "No changes yet."}
                </p>
              )}

              <form
                className="flex flex-col gap-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  if (document === undefined) {
                    return;
                  }
                  create.mutate({
                    document,
                    publish: true,
                    ...(note.trim().length === 0 ? {} : { note: note.trim() }),
                  });
                }}
              >
                <TextField
                  label="What changed"
                  value={note}
                  onChange={setNote}
                  hint="Shown beside the version in the history. The code view has no comments, so this is the record of why."
                />
                {create.isError ? (
                  <ErrorAlert message={describeError(create.error)} />
                ) : null}
                <div>
                  <SubmitButton
                    pending={create.isPending}
                    disabled={!changed || document === undefined}
                  >
                    Save and publish
                  </SubmitButton>
                </div>
              </form>
            </Panel>
          ) : null}

          {mayEdit && presets.data !== undefined ? (
            <Panel
              title="Start from a preset"
              description="Replaces the document in the editor. Nothing is saved until you publish."
            >
              <div className="flex flex-col gap-2">
                {presets.data.map((preset) => (
                  <div
                    key={preset.id}
                    className="border-base-300 flex flex-wrap items-start justify-between gap-2 border-b pb-2 last:border-b-0"
                  >
                    <div className="max-w-lg">
                      <p className="text-sm font-medium">{preset.name}</p>
                      <p className="text-base-content/70 text-xs">
                        {preset.description}
                      </p>
                      {preset.references.length > 0 ? (
                        <p className="text-base-content/60 mt-1 text-xs">
                          {/* The citation, because a preset asserts what another
                              system does with a token and this is how an operator
                              checks that claim. */}
                          Contract:{" "}
                          {preset.references.map((reference, index) => (
                            <span key={reference.url}>
                              {index === 0 ? null : ", "}
                              <a
                                className="link"
                                href={reference.url}
                                target="_blank"
                                rel="noreferrer"
                              >
                                {reference.label}
                              </a>
                            </span>
                          ))}
                        </p>
                      ) : null}
                    </div>
                    <button
                      type="button"
                      className="btn btn-outline btn-xs"
                      onClick={() => {
                        // Loading over unsaved work discards it, and nothing can
                        // bring it back - so that is asked, not assumed.
                        if (
                          (changed || issues.length > 0) &&
                          !globalThis.confirm(
                            `Load the ${preset.name} preset? Your unsaved edits are replaced and cannot be recovered.`,
                          )
                        ) {
                          return;
                        }
                        const parsed = parsePolicy(
                          JSON.stringify(preset.policy),
                        );
                        if (parsed.ok) {
                          applyDocument(withRuleIds(parsed.document));
                        }
                      }}
                    >
                      Load
                    </button>
                  </div>
                ))}
              </div>
            </Panel>
          ) : null}
        </div>

        {/* Sticky, so the simulator stays beside the rule being edited: the
            edit-simulate loop is the point of the page. */}
        <div className="xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)] xl:self-start xl:overflow-y-auto">
          <SimulatePanel
            tenant={tenant}
            endpointSlug={endpointSlug}
            document={document}
          />
          <VersionHistory
            versions={versions}
            mayEdit={mayEdit}
            publishing={publish.isPending}
            onPublish={(version) => {
              publish.mutate(version);
            }}
            error={publish.error}
          />
        </div>
      </div>
    </>
  );
}

/**
 * What state the draft is in, kept in the header so it is never scrolled away.
 *
 * Nothing is shown while the editor matches the published version: the badge
 * appearing is the signal, and a permanent "saved" would bury it.
 */
function DraftStatus({
  changed,
  issueCount,
}: Readonly<{ readonly changed: boolean; readonly issueCount: number }>) {
  if (issueCount > 0) {
    return (
      <span className="badge badge-error self-center">Draft has problems</span>
    );
  }
  if (changed) {
    return (
      <a
        href="#save-panel"
        className="badge badge-warning self-center"
        title="Go to the save panel"
      >
        Unsaved changes
      </a>
    );
  }
  return null;
}

/**
 * The builder, or an explanation of why it cannot be shown.
 *
 * Separated from the page so the "does the document parse?" decision is a component
 * boundary rather than a branch inside the layout.
 */
function BuilderPane({
  document,
  onChange,
  disabled,
}: Readonly<{
  readonly document: PolicyDocument | undefined;
  readonly onChange: (document: PolicyDocument) => void;
  readonly disabled: boolean;
}>) {
  if (document === undefined) {
    return (
      <Panel title="Rules">
        <ErrorAlert message="The document does not parse, so the builder cannot show it">
          <p className="text-sm">
            Switch to the code view to fix it. Nothing has been changed.
          </p>
        </ErrorAlert>
      </Panel>
    );
  }
  return (
    <RuleBuilder document={document} onChange={onChange} disabled={disabled} />
  );
}

/** Reads a stored version's document, giving every rule an identifier. */
function startingDocument(
  version: PolicyView | undefined,
): PolicyDocument | undefined {
  if (version === undefined) {
    return undefined;
  }
  const parsed = parsePolicy(JSON.stringify(version.document));
  return parsed.ok ? withRuleIds(parsed.document) : undefined;
}

interface VersionHistoryProps {
  readonly versions: readonly PolicyView[];
  readonly mayEdit: boolean;
  readonly publishing: boolean;
  readonly onPublish: (version: number) => void;
  readonly error: unknown;
}

/** Every version, with the published one marked and the others publishable. */
function VersionHistory({
  versions,
  mayEdit,
  publishing,
  onPublish,
  error,
}: Readonly<VersionHistoryProps>) {
  const columns: readonly Column<PolicyView>[] = [
    {
      key: "version",
      header: "Version",
      cell: (version) => (
        <div>
          <span className="font-mono text-sm">{version.version}</span>
          {version.published ? (
            <div>
              <StatusBadge tone="success">published</StatusBadge>
            </div>
          ) : null}
        </div>
      ),
    },
    {
      key: "note",
      header: "What changed",
      cell: (version) => (
        <div className="text-xs">
          <div>
            {version.note ?? (
              <span className="text-base-content/50">no note</span>
            )}
          </div>
          <div className="text-base-content/60">
            {formatInstant(version.createdAt)}
          </div>
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      cell: (version) =>
        mayEdit && !version.published ? (
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            disabled={publishing}
            onClick={() => {
              if (
                globalThis.confirm(
                  `Publish version ${String(version.version)}? Every token issued from now on uses it.`,
                )
              ) {
                onPublish(version.version);
              }
            }}
          >
            Publish
          </button>
        ) : null,
    },
  ];

  return (
    <Panel
      title="Versions"
      description="Immutable, so a rollback is a publish: republish the version before a mistake and nothing is edited."
    >
      {error === null ? null : <ErrorAlert message={describeError(error)} />}
      <DataTable
        columns={columns}
        rows={versions}
        rowKey={(version) => String(version.version)}
        empty={
          <p className="text-base-content/70 text-sm">
            No versions yet. Saving creates the first.
          </p>
        }
      />
    </Panel>
  );
}
