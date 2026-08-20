/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Form inputs, with their labels and their error messages.
 *
 * Every field takes its error from the same place: the map of field paths the admin
 * API returns when a request fails validation. That is what lets the server own the
 * rules - a length limit, a URL format, the fact that a public client may not hold a
 * secret - and the form show them against the right input without restating any of
 * them in the browser.
 *
 * Accessibility is structural rather than added: each field is a `fieldset` whose
 * `legend` is the label, the control is named from that legend with
 * `aria-labelledby`, and an error is linked with `aria-describedby` and marked
 * `aria-invalid`, so a screen reader reaches the message from the input.
 *
 * Every control carries `max-sm:text-base`, and that one class fixes the worst
 * mobile defect in the product. A mobile browser zooms the page when it focuses
 * an input whose text is under 16px - daisyUI's is 14px, and the monospace list
 * fields are 12px - and it does not zoom back out when the field is left, so a
 * form filled on a phone ends up sideways-scrolled through no action of the
 * reader's. Bumping the size responsively fixes it without touching the denser
 * rendering the desktop was designed around. The same reasoning gives the buttons
 * and the single-line controls `max-sm:min-h-11`: daisyUI's button and input are
 * both 40px tall, and a thumb wants 44.
 *
 * Author: John Grimes
 */

import { useId } from "react";

import { ErrorAlert, InfoAlert, Panel } from "./layout.js";
import { describeError } from "../api/errors.js";

import type { ReactNode } from "react";

/** The ids and validity a {@link FieldFrame} hands to its control. */
interface FieldFrameIds {
  readonly id: string;
  readonly labelledBy: string;
  readonly describedBy: string | undefined;
  readonly invalid: boolean;
}

interface FieldFrameProps {
  readonly label: string;
  /** A sentence explaining what the value is for, where it is not obvious. */
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  /** Receives the ids to attach to the control. */
  readonly children: (ids: FieldFrameIds) => ReactNode;
}

/**
 * The wiring shared by every string-valued control: identity, state, ARIA
 * linkage and the change handler.
 *
 * In one place so the text, textarea and select controls cannot drift apart in
 * how they link themselves to their frame and report validity to a screen
 * reader.
 */
function stringControlProps(
  frame: FieldFrameIds,
  value: string,
  onChange: (value: string) => void,
  disabled: boolean | undefined,
) {
  return {
    id: frame.id,
    value,
    disabled,
    "aria-invalid": frame.invalid,
    "aria-labelledby": frame.labelledBy,
    "aria-describedby": frame.describedBy,
    onChange: (event: {
      readonly currentTarget: { readonly value: string };
    }): void => {
      onChange(event.currentTarget.value);
    },
  };
}

/** The legend, hint and error around any control. */
function FieldFrame({
  label,
  hint,
  error,
  children,
}: Readonly<FieldFrameProps>) {
  const id = useId();
  const legendId = `${id}-legend`;
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy =
    [
      error === undefined ? undefined : errorId,
      hint === undefined ? undefined : hintId,
    ]
      .filter((value) => value !== undefined)
      .join(" ") || undefined;

  return (
    // `min-w-0` because a fieldset's UA default of `min-inline-size: min-content`
    // stops it shrinking inside the two-column grids, which is exactly the
    // sideways scroll the responsive classes elsewhere exist to prevent.
    <fieldset className="fieldset w-full min-w-0">
      {/* A legend cannot carry `htmlFor`, so the control points back at it with
          `aria-labelledby`. `whitespace-normal` because a long legend - "Maximum
          exchanged-token lifetime (seconds)" is the worst of them - must wrap
          rather than push the page sideways at 360px. */}
      <legend
        id={legendId}
        className="fieldset-legend whitespace-normal max-sm:text-base"
      >
        {label}
      </legend>
      {children({
        id,
        labelledBy: legendId,
        describedBy,
        invalid: error !== undefined,
      })}
      {hint === undefined ? null : (
        <p
          id={hintId}
          className="label whitespace-normal mt-1 text-xs max-sm:text-base"
        >
          {hint}
        </p>
      )}
      {error === undefined ? null : (
        <p id={errorId} className="text-error mt-1 text-xs max-sm:text-base">
          {error}
        </p>
      )}
    </fieldset>
  );
}

interface TextFieldProps {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  readonly type?: "text" | "password" | "email" | "url" | "number";
  readonly placeholder?: string;
  readonly required?: boolean;
  readonly autoComplete?: string;
  readonly disabled?: boolean;
}

/** A single-line text input. */
export function TextField({
  label,
  value,
  onChange,
  hint,
  error,
  type = "text",
  placeholder,
  required,
  autoComplete,
  disabled,
}: Readonly<TextFieldProps>) {
  return (
    <FieldFrame label={label} hint={hint} error={error}>
      {(frame) => (
        <input
          {...stringControlProps(frame, value, onChange, disabled)}
          type={type}
          className={`input input-bordered w-full max-sm:min-h-11 max-sm:text-base ${frame.invalid ? "input-error" : ""}`}
          placeholder={placeholder}
          required={required}
          autoComplete={autoComplete}
        />
      )}
    </FieldFrame>
  );
}

interface TextAreaFieldProps {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  readonly rows?: number;
  readonly monospace?: boolean;
  readonly disabled?: boolean | undefined;
}

/** A multi-line text input. */
export function TextAreaField({
  label,
  value,
  onChange,
  hint,
  error,
  rows = 4,
  monospace,
  disabled,
}: Readonly<TextAreaFieldProps>) {
  return (
    <FieldFrame label={label} hint={hint} error={error}>
      {(frame) => (
        <textarea
          {...stringControlProps(frame, value, onChange, disabled)}
          rows={rows}
          className={`textarea textarea-bordered w-full max-sm:text-base ${
            monospace === true ? "font-mono text-xs" : ""
          } ${frame.invalid ? "textarea-error" : ""}`}
        />
      )}
    </FieldFrame>
  );
}

interface SelectFieldProps {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly options: readonly {
    readonly value: string;
    readonly label: string;
  }[];
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  readonly disabled?: boolean;
}

/** A choice from a closed set. */
export function SelectField({
  label,
  value,
  onChange,
  options,
  hint,
  error,
  disabled,
}: Readonly<SelectFieldProps>) {
  return (
    <FieldFrame label={label} hint={hint} error={error}>
      {(frame) => (
        <select
          {...stringControlProps(frame, value, onChange, disabled)}
          className={`select select-bordered w-full max-sm:min-h-11 max-sm:text-base ${frame.invalid ? "select-error" : ""}`}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      )}
    </FieldFrame>
  );
}

interface CheckboxFieldProps {
  readonly label: string;
  readonly checked: boolean;
  readonly onChange: (checked: boolean) => void;
  readonly hint?: ReactNode;
  readonly disabled?: boolean;
}

/**
 * A single flag.
 *
 * Laid out with the control before the label, unlike the text inputs, because a
 * column of checkboxes reads as a list when the boxes align.
 *
 * The label wraps the box rather than only pointing at it, so that the tap target
 * is the whole row - a 16px box is not something to aim a thumb at, and growing
 * the box itself to 44px would make a column of them look like a form of buttons.
 * The hint sits outside the label, indented to the label's text, because a
 * paragraph of explanation is not part of the control's accessible name.
 */
export function CheckboxField({
  label,
  checked,
  onChange,
  hint,
  disabled,
}: Readonly<CheckboxFieldProps>) {
  const id = useId();
  const hintId = `${id}-hint`;

  return (
    <div className="py-1">
      <label
        className="flex cursor-pointer items-start gap-3 text-sm max-sm:min-h-11 max-sm:items-center max-sm:text-base"
        htmlFor={id}
      >
        <input
          id={id}
          type="checkbox"
          className="checkbox checkbox-sm mt-1 max-sm:mt-0"
          checked={checked}
          disabled={disabled}
          aria-describedby={hint === undefined ? undefined : hintId}
          onChange={(event) => {
            onChange(event.currentTarget.checked);
          }}
        />
        <span className="min-w-0">{label}</span>
      </label>
      {hint === undefined ? null : (
        <p
          id={hintId}
          className="text-base-content/60 ml-7 text-xs max-sm:text-base"
        >
          {hint}
        </p>
      )}
    </div>
  );
}

interface ListFieldProps {
  readonly label: string;
  /** One entry per line, as the operator types them. */
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  readonly rows?: number;
  readonly disabled?: boolean;
}

/**
 * A list of values, one per line.
 *
 * A textarea rather than a repeating row of inputs, because these lists - redirect
 * URIs, allowed scopes - are usually pasted from somewhere else, and pasting five
 * lines into five separate inputs is worse than editing text. The parsing lives in
 * `../forms/lists.js`, where it is tested.
 */
export function ListField({
  label,
  value,
  onChange,
  hint,
  error,
  rows = 3,
  disabled,
}: Readonly<ListFieldProps>) {
  return (
    <TextAreaField
      label={label}
      value={value}
      onChange={onChange}
      hint={hint}
      error={error}
      rows={rows}
      disabled={disabled}
      monospace
    />
  );
}

interface FormFooterProps {
  /** The mutation's failure, if it failed. */
  readonly error: unknown;
  /** Field-level issues, already rendered beside their inputs. */
  readonly issues: Readonly<Record<string, string>>;
  readonly pending: boolean;
  readonly submitLabel: string;
  /** Omit for a form that has nothing to cancel back to. */
  readonly onCancel?: () => void;
  readonly disabled?: boolean;
}

/**
 * The bottom of a form: what went wrong, and the two things to do about it.
 *
 * The general error is shown only when there are no field-level issues. When there
 * are, they are already beside the inputs that caused them, and repeating "that
 * request is not valid" above the button says nothing the reader cannot see.
 */
export function FormFooter({
  error,
  issues,
  pending,
  submitLabel,
  onCancel,
  disabled,
}: Readonly<FormFooterProps>) {
  const showGeneral = error !== null && Object.keys(issues).length === 0;

  return (
    <>
      {showGeneral ? <ErrorAlert message={describeError(error)} /> : null}
      <div className="flex flex-wrap gap-2">
        <SubmitButton pending={pending} disabled={disabled}>
          {submitLabel}
        </SubmitButton>
        {onCancel === undefined ? null : (
          <button
            type="button"
            className="btn btn-ghost max-sm:min-h-11 max-sm:text-base"
            onClick={onCancel}
          >
            Cancel
          </button>
        )}
      </div>
    </>
  );
}

/**
 * The sentence every patch form ends its description with.
 *
 * Appended by {@link PatchForm} rather than written at each call site, so the forms
 * that behave this way cannot end up describing themselves differently.
 */
const PATCH_FORM_NOTE =
  "Only the fields you change are sent, so saving with nothing changed writes nothing. A value the API refuses is reported under the field that caused it.";

/**
 * A panel holding a form that sends a patch.
 *
 * The guard lives here rather than in each page: `onSave` is not called when there is
 * nothing to send, so no form built this way can post an empty patch. Pair it with
 * {@link SaveRow}, which says the same thing to the operator before they press
 * anything - the disabled button is a hint, this is the rule.
 *
 * The description is what this particular form decides, and {@link PATCH_FORM_NOTE}
 * is appended to it; a form with nothing extra to say passes none.
 */
export function PatchForm({
  title,
  description,
  hasChanges,
  onSave,
  children,
}: Readonly<{
  readonly title: string;
  readonly description?: string | undefined;
  readonly hasChanges: boolean;
  readonly onSave: () => void;
  readonly children: ReactNode;
}>) {
  return (
    <Panel
      title={title}
      description={
        description === undefined
          ? PATCH_FORM_NOTE
          : `${description} ${PATCH_FORM_NOTE}`
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (hasChanges) {
            onSave();
          }
        }}
      >
        {children}
      </form>
    </Panel>
  );
}

/**
 * What a patch form says after a save: what went wrong, or that it worked.
 *
 * The general error is shown only when there are no field-level issues, for the same
 * reason {@link FormFooter} does it: when there are, they are already beside the
 * inputs that caused them, and repeating "that request is not valid" above the button
 * says nothing the reader cannot see.
 *
 * Silence is not an option either way - every operation reports its own outcome - so
 * this is one component rather than the same pair of conditionals in every form.
 */
export function SaveOutcome({
  error,
  issues,
  isSuccess,
  saved,
}: Readonly<{
  readonly error: unknown;
  /** The field-level issues already rendered against their inputs. */
  readonly issues: Readonly<Record<string, string>>;
  readonly isSuccess: boolean;
  /** What to say on success, naming the thing that was saved. */
  readonly saved: string;
}>) {
  return (
    <>
      {error !== null && Object.keys(issues).length === 0 ? (
        <ErrorAlert message={describeError(error)} />
      ) : null}
      {isSuccess ? <InfoAlert>{saved}</InfoAlert> : null}
    </>
  );
}

/**
 * The save button of a patch form, with the reason it is disabled beside it.
 *
 * A save with nothing changed must send nothing: the admin API accepts an empty patch
 * and records an audit event naming no fields, which is a write nobody asked for and
 * nobody can undo. Disabling the button is how that becomes visible before it is
 * pressed - silence would leave the operator pressing a button that does nothing.
 *
 * {@link PatchForm} guards the submit on the same condition, so a form built from the
 * two cannot send an empty patch even if the button is reached another way.
 *
 * `disabledReason` overrides what is said when there is a reason other than an
 * unedited form - a field the form itself refuses, which would otherwise be reported
 * as "Nothing has changed." to somebody who had just typed something.
 */
export function SaveRow({
  label,
  hasChanges,
  pending,
  disabledReason,
  className,
}: Readonly<{
  readonly label: string;
  readonly hasChanges: boolean;
  readonly pending: boolean;
  readonly disabledReason?: string | undefined;
  readonly className?: string | undefined;
}>) {
  return (
    <div className={`flex flex-wrap items-center gap-3 ${className ?? ""}`}>
      <SubmitButton pending={pending} disabled={!hasChanges}>
        {label}
      </SubmitButton>
      {hasChanges ? null : (
        <span className="text-base-content/60 text-xs max-sm:text-base">
          {disabledReason ?? "Nothing has changed."}
        </span>
      )}
    </div>
  );
}

/** A submit button that shows progress and cannot be pressed twice. */
export function SubmitButton({
  children,
  pending,
  disabled,
}: Readonly<{
  readonly children: ReactNode;
  readonly pending?: boolean | undefined;
  readonly disabled?: boolean | undefined;
}>) {
  return (
    <button
      type="submit"
      className="btn btn-sm btn-primary max-sm:min-h-11 max-sm:text-base"
      disabled={pending === true || disabled === true}
    >
      {pending === true ? (
        <span className="loading loading-spinner loading-xs" />
      ) : null}
      {children}
    </button>
  );
}
