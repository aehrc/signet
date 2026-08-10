/**
 * Form inputs, with their labels and their error messages.
 *
 * Every field takes its error from the same place: the map of field paths the admin
 * API returns when a request fails validation. That is what lets the server own the
 * rules - a length limit, a URL format, the fact that a public client may not hold a
 * secret - and the form show them against the right input without restating any of
 * them in the browser.
 *
 * Accessibility is structural rather than added: the label is associated by `id`
 * from `useId`, and an error is linked with `aria-describedby` and marked
 * `aria-invalid`, so a screen reader reaches the message from the input.
 *
 * Author: John Grimes
 */

import { useId } from "react";

import { ErrorAlert, Panel } from "./layout.js";
import { describeError } from "../api/errors.js";

import type { ReactNode } from "react";

interface FieldFrameProps {
  readonly label: string;
  /** A sentence explaining what the value is for, where it is not obvious. */
  readonly hint?: ReactNode;
  readonly error?: string | undefined;
  /** Receives the ids to attach to the control. */
  readonly children: (ids: {
    readonly id: string;
    readonly describedBy: string | undefined;
    readonly invalid: boolean;
  }) => ReactNode;
}

/** The label, hint and error around any control. */
function FieldFrame({
  label,
  hint,
  error,
  children,
}: Readonly<FieldFrameProps>) {
  const id = useId();
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
    <div className="form-control w-full">
      <label className="label" htmlFor={id}>
        <span className="label-text">{label}</span>
      </label>
      {children({ id, describedBy, invalid: error !== undefined })}
      {hint === undefined ? null : (
        <p id={hintId} className="text-base-content/60 mt-1 text-xs">
          {hint}
        </p>
      )}
      {error === undefined ? null : (
        <p id={errorId} className="text-error mt-1 text-xs">
          {error}
        </p>
      )}
    </div>
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
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          type={type}
          className={`input input-bordered w-full ${invalid ? "input-error" : ""}`}
          value={value}
          placeholder={placeholder}
          required={required}
          autoComplete={autoComplete}
          disabled={disabled}
          aria-invalid={invalid}
          aria-describedby={describedBy}
          onChange={(event) => {
            onChange(event.currentTarget.value);
          }}
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
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          rows={rows}
          className={`textarea textarea-bordered w-full ${
            monospace === true ? "font-mono text-xs" : ""
          } ${invalid ? "textarea-error" : ""}`}
          value={value}
          disabled={disabled}
          aria-invalid={invalid}
          aria-describedby={describedBy}
          onChange={(event) => {
            onChange(event.currentTarget.value);
          }}
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
      {({ id, describedBy, invalid }) => (
        <select
          id={id}
          className={`select select-bordered w-full ${invalid ? "select-error" : ""}`}
          value={value}
          disabled={disabled}
          aria-invalid={invalid}
          aria-describedby={describedBy}
          onChange={(event) => {
            onChange(event.currentTarget.value);
          }}
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
    <div className="flex items-start gap-3 py-1">
      <input
        id={id}
        type="checkbox"
        className="checkbox checkbox-sm mt-1"
        checked={checked}
        disabled={disabled}
        aria-describedby={hint === undefined ? undefined : hintId}
        onChange={(event) => {
          onChange(event.currentTarget.checked);
        }}
      />
      <div>
        <label className="cursor-pointer text-sm" htmlFor={id}>
          {label}
        </label>
        {hint === undefined ? null : (
          <p id={hintId} className="text-base-content/60 text-xs">
            {hint}
          </p>
        )}
      </div>
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
      <div className="flex gap-2">
        <SubmitButton pending={pending} disabled={disabled}>
          {submitLabel}
        </SubmitButton>
        {onCancel === undefined ? null : (
          <button type="button" className="btn btn-ghost" onClick={onCancel}>
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
 * The save button of a patch form, with the reason it is disabled beside it.
 *
 * A save with nothing changed must send nothing: the admin API accepts an empty patch
 * and records an audit event naming no fields, which is a write nobody asked for and
 * nobody can undo. Disabling the button is how that becomes visible before it is
 * pressed - silence would leave the operator pressing a button that does nothing.
 *
 * {@link PatchForm} guards the submit on the same condition, so a form built from the
 * two cannot send an empty patch even if the button is reached another way.
 */
export function SaveRow({
  label,
  hasChanges,
  pending,
  className,
}: Readonly<{
  readonly label: string;
  readonly hasChanges: boolean;
  readonly pending: boolean;
  readonly className?: string | undefined;
}>) {
  return (
    <div className={`flex items-center gap-3 ${className ?? ""}`}>
      <SubmitButton pending={pending} disabled={!hasChanges}>
        {label}
      </SubmitButton>
      {hasChanges ? null : (
        <span className="text-base-content/60 text-xs">
          Nothing has changed.
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
      className="btn btn-primary"
      disabled={pending === true || disabled === true}
    >
      {pending === true ? (
        <span className="loading loading-spinner loading-xs" />
      ) : null}
      {children}
    </button>
  );
}
