/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The application root: providers and routes.
 *
 * One bundle serves three surfaces - the console, the end-user authorization pages
 * and the developer portal - because they share a shell, a stylesheet and a theme,
 * and splitting them would be three deployments to keep looking alike. They are
 * separated by route rather than by build.
 *
 * The query defaults are deliberate. Nothing retries by default: an admin API
 * refusal is an answer, and retrying a 403 three times only delays showing the
 * operator what happened. Refetching on focus is off for the same reason it is
 * usually on - this is configuration rather than a live feed, and a page that
 * silently reloaded while a form was open would discard what was being typed.
 *
 * Author: John Grimes
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";

import { AuditPage } from "./console/auditPage.js";
import { ClientDetailPage } from "./console/clientDetailPage.js";
import { ClientsPage } from "./console/clientsPage.js";
import { ConsoleLayout } from "./console/consoleLayout.js";
import { EndpointLayout } from "./console/endpointLayout.js";
import { EndpointOverviewPage } from "./console/endpointOverviewPage.js";
import { EndpointsPage } from "./console/endpointsPage.js";
import { FederationPage } from "./console/federationPage.js";
import { KeysPage } from "./console/keysPage.js";
import { LaunchPage } from "./console/launchPage.js";
import { RequestsPage } from "./console/requestsPage.js";
import { CONSOLE_BASE, SIGN_IN_ROUTE } from "./console/routes.js";
import { SignInPage } from "./console/signInPage.js";
import { TenantSettingsPage } from "./console/tenantSettingsPage.js";
import { TrustPage } from "./console/trustPage.js";
import { UserDetailPage } from "./console/userDetailPage.js";
import { UsersPage } from "./console/usersPage.js";
import {
  ConsentPage,
  LoginPage,
  PickerPage,
} from "./endUser/interactionPages.js";
import { ManagePage } from "./endUser/managePage.js";
import { PortalPage } from "./endUser/portalPage.js";
import { PolicyPage } from "./policy/policyPage.js";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
  },
});

/** Application root: providers plus the route table. */
export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path={SIGN_IN_ROUTE} element={<SignInPage />} />

          <Route path={CONSOLE_BASE} element={<ConsoleLayout />}>
            {/* No tenant named: the layout redirects, or offers the choice. */}
            <Route index element={<TenantRedirectNotice />} />
          </Route>

          <Route path={`${CONSOLE_BASE}/t/:tenant`} element={<ConsoleLayout />}>
            <Route index element={<EndpointsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="settings" element={<TenantSettingsPage />} />

            <Route path="e/:endpoint" element={<EndpointLayout />}>
              <Route index element={<EndpointOverviewPage />} />
              <Route path="clients" element={<ClientsPage />} />
              <Route path="clients/:clientId" element={<ClientDetailPage />} />
              <Route path="policy" element={<PolicyPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="users/:userId" element={<UserDetailPage />} />
              <Route path="keys" element={<KeysPage />} />
              <Route path="identity" element={<FederationPage />} />
              <Route path="trust" element={<TrustPage />} />
              <Route path="requests" element={<RequestsPage />} />
              <Route path="launch" element={<LaunchPage />} />
            </Route>
          </Route>

          {/*
            The end-user surfaces, under an endpoint's own issuer path. Those URLs are
            what `/authorize` redirects to and what the discovery document advertises as
            the management endpoint, so they are fixed rather than ours to choose.
          */}
          <Route path="/t/:tenant/e/:endpoint/login" element={<LoginPage />} />
          <Route
            path="/t/:tenant/e/:endpoint/picker"
            element={<PickerPage />}
          />
          <Route
            path="/t/:tenant/e/:endpoint/consent"
            element={<ConsentPage />}
          />
          <Route
            path="/t/:tenant/e/:endpoint/manage"
            element={<ManagePage />}
          />
          <Route path="/t/:tenant/e/:endpoint/apps" element={<PortalPage />} />

          {/* Anything else lands on the console, which decides where to go. */}
          <Route path="*" element={<Navigate to={CONSOLE_BASE} replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

/**
 * What the console's index renders while the layout decides where to send it.
 *
 * The layout redirects to the caller's only tenant, or shows a chooser, before this
 * is reached - so it exists to give the route an element rather than to be seen.
 */
function TenantRedirectNotice() {
  return null;
}
