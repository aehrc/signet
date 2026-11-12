/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The tenant's logo: what its end users see in place of the Signet wordmark.
 *
 * The preview draws each colour scheme in that scheme's own theme, by nesting a
 * `data-theme`, rather than in whichever scheme the operator's own system happens to
 * be in. A logo with dark lettering looks fine on the operator's light screen and is
 * invisible to a patient whose phone is in dark mode, and the only way to see that
 * before the patient does is to be shown both.
 *
 * Author: John Grimes
 */

import { describeError } from "../api/errors.js";
import { useRemoveLogo, useUploadLogo } from "../api/queries.js";
import { ErrorAlert, InfoAlert, Loading, Panel } from "../components/layout.js";
import { useTenantBranding } from "../endUser/queries.js";

import type { LogoVariant, TenantBranding } from "@signet/core";

/** What the file picker offers. The server decides from the bytes regardless. */
const ACCEPTED_FILES =
  "image/png,image/jpeg,image/webp,image/svg+xml,.png,.jpg,.jpeg,.webp,.svg";

/** How each variant is named in the panel and in its outcome messages. */
const VARIANT_LABELS: Readonly<Record<LogoVariant, string>> = {
  light: "Logo",
  dark: "Dark-scheme variant",
};

interface LogoPanelProps {
  readonly tenant: string;
  readonly mayAdminister: boolean;
}

/** The tenant's logo and its dark-scheme variant, with a preview of each scheme. */
export function LogoPanel({ tenant, mayAdminister }: Readonly<LogoPanelProps>) {
  const branding = useTenantBranding(tenant);
  const upload = useUploadLogo(tenant);
  const removal = useRemoveLogo(tenant);
  const pending = upload.isPending || removal.isPending;

  return (
    <Panel
      title="Logo"
      description="Shown in place of the Signet wordmark on this tenant's sign-in, consent and other end-user pages, and in this console's sidebar. The pages are then titled with the tenant's name. PNG, JPEG, WebP or SVG, up to 256 KB."
    >
      {branding === undefined ? (
        <Loading />
      ) : (
        <>
          <Preview branding={branding} />
          {mayAdminister ? (
            <div className="flex flex-col gap-4">
              {(["light", "dark"] as const).map((variant) => (
                <VariantRow
                  key={variant}
                  variant={variant}
                  held={
                    variant === "light"
                      ? branding !== null
                      : (branding?.darkLogoUrl ?? null) !== null
                  }
                  // A dark variant replaces the logo, so there must be one first.
                  disabledReason={
                    variant === "dark" && branding === null
                      ? "Upload the logo first."
                      : undefined
                  }
                  pending={pending}
                  onChoose={(file) => {
                    removal.reset();
                    upload.mutate({ variant, file });
                  }}
                  onRemove={() => {
                    const consequence =
                      variant === "light"
                        ? " Its dark-scheme variant is removed with it, and the pages go back to the Signet wordmark."
                        : "";
                    if (
                      globalThis.confirm(
                        `Remove the ${VARIANT_LABELS[variant].toLowerCase()}?${consequence}`,
                      )
                    ) {
                      upload.reset();
                      removal.mutate(variant);
                    }
                  }}
                />
              ))}
            </div>
          ) : (
            <p className="text-base-content/70 text-sm max-sm:text-base">
              Only an owner or an admin may change the logo.
            </p>
          )}
        </>
      )}

      {upload.isPending ? <Loading label="Uploading…" /> : null}
      {removal.isPending ? <Loading label="Removing…" /> : null}
      {upload.isError ? (
        <ErrorAlert message={describeError(upload.error)} />
      ) : null}
      {removal.isError ? (
        <ErrorAlert message={describeError(removal.error)} />
      ) : null}
      {upload.isSuccess ? (
        <InfoAlert>
          {VARIANT_LABELS[upload.variables.variant]} uploaded.
        </InfoAlert>
      ) : null}
      {removal.isSuccess ? (
        <InfoAlert>{VARIANT_LABELS[removal.variables]} removed.</InfoAlert>
      ) : null}
    </Panel>
  );
}

/** The header each colour scheme will show, drawn in that scheme's theme. */
function Preview({ branding }: Readonly<{ branding: TenantBranding | null }>) {
  const schemes = [
    { theme: "light", label: "Light scheme", url: branding?.logoUrl },
    {
      theme: "dark",
      label: "Dark scheme",
      url: branding?.darkLogoUrl ?? branding?.logoUrl,
    },
  ] as const;

  return (
    <div className="flex flex-wrap gap-3">
      {schemes.map((scheme) => (
        <figure
          key={scheme.theme}
          data-theme={scheme.theme}
          className="bg-base-200 text-base-content border-base-300 flex min-w-48 flex-1 flex-col items-center gap-2 rounded-box border p-4"
        >
          <div className="flex h-10 items-center">
            {scheme.url === undefined ? (
              <span className="text-xl font-bold">Signet</span>
            ) : (
              <img
                src={scheme.url}
                alt={`${branding?.name ?? ""} in the ${scheme.label.toLowerCase()}`}
                className="h-10 w-auto max-w-full object-contain"
              />
            )}
          </div>
          <figcaption className="text-base-content/70 text-xs max-sm:text-base">
            {scheme.label}
          </figcaption>
        </figure>
      ))}
    </div>
  );
}

interface VariantRowProps {
  readonly variant: LogoVariant;
  /** Whether the tenant currently holds this variant. */
  readonly held: boolean;
  readonly disabledReason: string | undefined;
  readonly pending: boolean;
  readonly onChoose: (file: File) => void;
  readonly onRemove: () => void;
}

/** Upload, replace or remove one variant. */
function VariantRow({
  variant,
  held,
  disabledReason,
  pending,
  onChoose,
  onRemove,
}: Readonly<VariantRowProps>) {
  const label = VARIANT_LABELS[variant];
  const inputId = `logo-${variant}`;

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={inputId} className="text-sm font-medium max-sm:text-base">
        {held
          ? `Replace the ${label.toLowerCase()}`
          : `Upload a ${label.toLowerCase()}`}
      </label>
      <div className="flex flex-wrap items-center gap-3">
        <input
          id={inputId}
          type="file"
          accept={ACCEPTED_FILES}
          className="file-input file-input-sm max-sm:file-input-md w-full max-w-xs"
          disabled={pending || disabledReason !== undefined}
          onChange={(event) => {
            const file = event.target.files?.[0];
            // Cleared so that choosing the same file again is still a change.
            event.target.value = "";
            if (file !== undefined) {
              onChoose(file);
            }
          }}
        />
        {held ? (
          <button
            type="button"
            className="btn btn-ghost btn-sm text-error"
            disabled={pending}
            onClick={onRemove}
          >
            Remove
          </button>
        ) : null}
      </div>
      <span className="text-base-content/60 text-xs max-sm:text-base">
        {disabledReason ??
          (variant === "light"
            ? "Shown on every end-user page."
            : "Optional. Shown instead of the logo when the reader's system uses a dark colour scheme.")}
      </span>
    </div>
  );
}
