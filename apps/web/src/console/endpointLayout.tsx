/**
 * The frame around one endpoint's pages.
 *
 * Loads the endpoint once and shares it, so a page that needs a capability flag or
 * the issuer does not fetch it again. The tabs are the endpoint's resources, which is
 * also the shape of the API below it.
 *
 * Author: John Grimes
 */

import { NavLink, Outlet, useParams } from "react-router";

import { endpointRoute, ENDPOINT_TABS } from "./routes.js";
import { useConsoleContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useEndpoint } from "../api/queries.js";
import { ErrorAlert, Loading, PageHeader } from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";

import type { ConsoleContext } from "./consoleLayout.js";
import type { EndpointView } from "../api/types.js";

/** What every endpoint page can read from its parent. */
export interface EndpointContext extends ConsoleContext {
  readonly endpointSlug: string;
  readonly endpoint: EndpointView;
}

/** Loads the endpoint named in the URL and renders its tabs. */
export function EndpointLayout() {
  const console_ = useConsoleContext();
  const { endpoint: endpointSlug } = useParams<{ endpoint: string }>();
  const endpoint = useEndpoint(console_.tenant, endpointSlug ?? "");

  if (endpoint.isPending) {
    return <Loading label="Loading the endpoint…" />;
  }
  if (endpoint.isError || endpoint.data === undefined) {
    return <ErrorAlert message={describeError(endpoint.error)} />;
  }

  const context: EndpointContext = {
    ...console_,
    endpointSlug: endpointSlug ?? "",
    endpoint: endpoint.data,
  };

  return (
    <>
      <PageHeader
        title={endpoint.data.name}
        description={
          <>
            <span className="font-mono text-xs">{endpoint.data.issuer}</span>
            <span className="mx-2">·</span>
            <span>fronting {endpoint.data.fhirBaseUrl}</span>
          </>
        }
        actions={
          <>
            <StatusBadge tone={toneForStatus(endpoint.data.status)}>
              {endpoint.data.status}
            </StatusBadge>
            {endpoint.data.isProduction ? null : (
              <StatusBadge tone="info">non-production</StatusBadge>
            )}
          </>
        }
      />

      {/* The tabs wrap onto four rows at 360px, which is fine; what is not is
          daisyUI's 40px tab height, four pixels under what a thumb needs. */}
      <div
        role="tablist"
        className="tabs tabs-border mb-6 max-sm:[&_.tab]:min-h-11"
      >
        {ENDPOINT_TABS.map((tab) => (
          <NavLink
            key={tab.path}
            role="tab"
            // `end` only for the overview: every other tab has pages beneath it,
            // and an exact match would deselect the tab on a detail page.
            end={tab.path === ""}
            to={endpointRoute(console_.tenant, endpointSlug ?? "", tab.path)}
            className={({ isActive }) =>
              `tab gap-1.5 ${isActive ? "tab-active" : ""}`
            }
          >
            <tab.icon size={14} />
            {tab.label}
          </NavLink>
        ))}
      </div>

      <Outlet context={context} />
    </>
  );
}
