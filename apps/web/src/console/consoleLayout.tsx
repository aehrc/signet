/**
 * The console's frame, and the gate in front of it.
 *
 * Two responsibilities, both of which have to happen before any page renders. The
 * session is read once here and shared through the router's outlet context, so a page
 * never has to ask again - and a caller who is not signed in is sent to the sign-in
 * page rather than being shown a shell full of failed queries.
 *
 * The tenant comes from the URL, not from a stored preference. A bookmark or a link
 * shared with a colleague must open the same tenant it did for the person who sent
 * it, and a "current tenant" in local storage would make the same URL mean different
 * things to different people.
 *
 * Author: John Grimes
 */

import { GearIcon, LogIcon, ServerIcon } from "@primer/octicons-react";
import { useState } from "react";
import { Navigate, NavLink, Outlet, useParams } from "react-router";

import { AccountMenu } from "./accountMenu.js";
import { PasskeyDialog } from "./passkeyDialog.js";
import { SIGN_IN_ROUTE, tenantRoute } from "./routes.js";
import { useSession, useSignOut } from "../api/queries.js";
import { AppShell, CentredShell } from "../components/appShell.js";
import { EmptyState, ErrorAlert, Loading } from "../components/layout.js";

import type { SessionView } from "../api/types.js";

/** What every console page can read from its parent. */
export interface ConsoleContext {
  readonly session: SessionView;
  readonly tenant: string;
  /** The role the caller holds in this tenant. */
  readonly role: string;
}

/** daisyUI's active class, applied by `NavLink` when the route matches. */
function navClass({ isActive }: { isActive: boolean }): string {
  return isActive ? "active" : "";
}

/**
 * Requires a session, and renders the console frame around whatever is inside.
 *
 * The gate is a redirect rather than a rendered sign-in form, so the address bar
 * matches what is on screen and a reload after signing in returns to the console.
 */
export function ConsoleLayout() {
  const session = useSession();
  const signOut = useSignOut();
  const { tenant } = useParams<{ tenant?: string }>();
  const [passkeysOpen, setPasskeysOpen] = useState(false);

  if (session.isPending) {
    return (
      <CentredShell title="Signet">
        <Loading label="Checking your session…" />
      </CentredShell>
    );
  }

  if (session.isError || session.data === undefined) {
    return <Navigate to={SIGN_IN_ROUTE} replace />;
  }

  const tenants = session.data.tenants;

  // No tenant in the URL: send the reader to their only one, or make them choose.
  if (tenant === undefined) {
    if (tenants.length === 1 && tenants[0] !== undefined) {
      return <Navigate to={tenantRoute(tenants[0].slug)} replace />;
    }
    return <TenantChooser session={session.data} />;
  }

  const membership = tenants.find((candidate) => candidate.slug === tenant);
  if (membership === undefined) {
    return (
      <AppShell title="Signet">
        <ErrorAlert message="You are not a member of that tenant">
          <p className="text-sm">
            It may not exist, or your membership may have been removed. Pick one
            you do belong to from the list.
          </p>
        </ErrorAlert>
        <div className="mt-4">
          <TenantList session={session.data} />
        </div>
      </AppShell>
    );
  }

  const context: ConsoleContext = {
    session: session.data,
    tenant,
    role: membership.role,
  };

  return (
    <AppShell
      title={membership.name ?? tenant}
      navbarEnd={
        <>
          {tenants.length > 1 ? (
            <TenantSwitcher tenant={tenant} tenants={tenants} />
          ) : null}
          <AccountMenu
            label={
              session.data.user?.email ?? session.data.token?.name ?? "Account"
            }
            signingOut={signOut.isPending}
            // Absent for a personal access token: it is not a person, holds no
            // password, and has no passkeys to manage.
            {...(session.data.user === undefined
              ? {}
              : {
                  onManagePasskeys: () => {
                    setPasskeysOpen(true);
                  },
                })}
            onSignOut={() => {
              signOut.mutate(undefined, {
                onSuccess: () => {
                  globalThis.location.assign(SIGN_IN_ROUTE);
                },
              });
            }}
          />
          <PasskeyDialog
            open={passkeysOpen}
            onClose={() => {
              setPasskeysOpen(false);
            }}
          />
        </>
      }
      navigation={
        <>
          <li>
            <NavLink end to={tenantRoute(tenant)} className={navClass}>
              <ServerIcon />
              Endpoints
            </NavLink>
          </li>
          <li>
            <NavLink to={tenantRoute(tenant, "/audit")} className={navClass}>
              <LogIcon />
              Audit
            </NavLink>
          </li>
          <li>
            <NavLink to={tenantRoute(tenant, "/settings")} className={navClass}>
              <GearIcon />
              Tenant settings
            </NavLink>
          </li>
        </>
      }
    >
      <Outlet context={context} />
    </AppShell>
  );
}

/**
 * The navbar control that moves between the tenants a person belongs to.
 *
 * Exported, and a component rather than markup inside {@link ConsoleLayout},
 * because it is the console's only form control outside `components/fields.js`
 * and it needs the same mobile sizing they carry - 44px tall and 16px of text
 * below `sm`, so a thumb can hit it and the browser does not zoom the page when
 * it opens. It renders only for somebody who belongs to more than one tenant,
 * which the end-to-end stack's single seeded tenant never produces, so its markup
 * is what proves the sizing.
 *
 * Navigating assigns the location rather than routing, so the whole console
 * remounts: every query in flight belongs to the tenant being left, and a soft
 * navigation would show the new tenant's pages with the old tenant's data in them
 * until each one refetched.
 *
 * `tenant` is the slug currently in the URL, which is the selected option;
 * `tenants` is every tenant the caller may act on, as the session reports them.
 */
export function TenantSwitcher({
  tenant,
  tenants,
}: Readonly<{
  readonly tenant: string;
  readonly tenants: SessionView["tenants"];
}>) {
  return (
    <select
      className="select select-bordered select-sm max-w-40 max-sm:min-h-11 max-sm:text-base"
      aria-label="Switch tenant"
      value={tenant}
      onChange={(event) => {
        globalThis.location.assign(tenantRoute(event.currentTarget.value));
      }}
    >
      {tenants.map((candidate) => (
        <option key={candidate.slug} value={candidate.slug}>
          {candidate.name ?? candidate.slug}
        </option>
      ))}
    </select>
  );
}

/** The page shown when a person belongs to several tenants and named none. */
function TenantChooser({ session }: Readonly<{ session: SessionView }>) {
  return (
    <CentredShell
      title="Choose a tenant"
      subtitle="A tenant owns endpoints, clients and policies. You are a member of more than one."
    >
      <TenantList session={session} />
    </CentredShell>
  );
}

/** The list of tenants the caller may act on. */
function TenantList({ session }: Readonly<{ session: SessionView }>) {
  if (session.tenants.length === 0) {
    return (
      <EmptyState
        title="You are not a member of any tenant"
        description="A tenant owner has to add you before you can see anything. Ask whoever administers this deployment."
      />
    );
  }

  return (
    <ul className="menu bg-base-100 w-full">
      {session.tenants.map((tenant) => (
        <li key={tenant.slug}>
          <a href={tenantRoute(tenant.slug)}>
            <span className="flex-1">{tenant.name ?? tenant.slug}</span>
            <span className="badge badge-sm">{tenant.role}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}
