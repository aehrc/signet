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
 * The two columns are a desktop arrangement and nothing more. Below `xl` the page is one
 * column, and the column wrappers dissolve so that the panels can be put in the order a
 * phone wants rather than the order two columns needed: rules, then the simulator that
 * answers for them, then saving, presets and the history. Nothing is dropped on the way
 * down - every control the desktop offers is in the single column too.
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
            {/* daisyUI's `tabs-sm` is 32px, which is fine beside a pointer and
                twelve pixels under what a thumb needs. Sized on the list rather
                than on each tab, as the endpoint's own tab strip does. */}
            <div
              role="tablist"
              className="tabs tabs-box tabs-sm max-sm:[&_.tab]:min-h-11"
            >
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

      {/* A flex column on a phone and a two-column grid at `xl`. Not a grid at
          both widths: a single implicit grid track is sized to its content, and
          a panel holding an unbroken issuer URL or a paragraph of description
          therefore made the track - and with it the page - 1370px wide at
          360px. A block-level flex column takes the width it is given. */}
      <div className="flex flex-col xl:grid xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:gap-6">
        {/* `contents` dissolves each column below `xl`, so the panels inside
            become items of the page's own column and the `order-*` classes can
            interleave the two. Without it the simulator - the other half of the
            edit-simulate loop this page exists for - sits below the save panel,
            the presets and everything else the left column holds. */}
        <div className="contents xl:block">
          <div className="order-1">
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
          </div>

          {mayEdit ? (
            <div className="order-3">
              <Panel
                id="save-panel"
                title="Save"
                description="Creates a new version. Publishing it makes it the one every token is issued under."
              >
                {changed && document !== undefined && starting !== undefined ? (
                  <PolicyDiff
                    before={formatPolicy(
                      startingDocument(starting) ?? document,
                    )}
                    after={formatPolicy(document)}
                  />
                ) : (
                  <p className="text-base-content/70 text-sm max-sm:text-base">
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
                      ...(note.trim().length === 0
                        ? {}
                        : { note: note.trim() }),
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
            </div>
          ) : null}

          {mayEdit && presets.data !== undefined ? (
            <div className="order-4">
              <Panel
                title="Start from a preset"
                description="Replaces the document in the editor. Nothing is saved until you publish."
              >
                {/* Flex rows rather than DaisyUI's grid-based list-row, so the
                    Load button centres vertically against the variable-height
                    text block beside it. */}
                <ul className="flex flex-col">
                  {presets.data.map((preset) => (
                    <li
                      key={preset.id}
                      className="flex items-center gap-4 py-3 first:pt-0 last:pb-0"
                    >
                      <div className="max-w-lg flex-1">
                        <p className="text-sm max-sm:text-base font-medium">
                          {preset.name}
                        </p>
                        <p className="text-base-content/70 text-xs max-sm:text-base">
                          {preset.description}
                        </p>
                        {preset.references.length > 0 ? (
                          <p className="text-base-content/60 mt-1 text-xs max-sm:text-base">
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
                        className="btn btn-outline btn-sm"
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
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          ) : null}
        </div>

        {/* Sticky at `xl`, so the simulator stays beside the rule being edited:
            the edit-simulate loop is the point of the page. Below `xl` there is
            no second column to stay beside, and a sticky element in a single
            column is a panel that covers what is under it. */}
        <div className="contents xl:sticky xl:top-4 xl:block xl:max-h-[calc(100vh-2rem)] xl:self-start xl:overflow-y-auto">
          <div className="order-2">
            <SimulatePanel
              tenant={tenant}
              endpointSlug={endpointSlug}
              document={document}
            />
          </div>
          <div className="order-5">
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
      <span className="badge badge-error self-center max-sm:min-h-11">
        Draft has problems
      </span>
    );
  }
  if (changed) {
    return (
      // A link, so it is something a thumb has to hit: a badge is 20px tall,
      // and this one is the way back to the save panel from anywhere on a page
      // that is nine panels long on a phone.
      <a
        href="#save-panel"
        className="badge badge-warning self-center max-sm:min-h-11"
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
          <p className="text-sm max-sm:text-base">
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
          <p className="text-base-content/70 text-sm max-sm:text-base">
            No versions yet. Saving creates the first.
          </p>
        }
      />
    </Panel>
  );
}
