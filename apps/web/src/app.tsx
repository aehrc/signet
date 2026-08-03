import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AppShell } from "./components/appShell.js";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
});

/** Placeholder console landing view; replaced by the real console in phase 4. */
function ConsoleHome() {
  return (
    <div className="card bg-base-100 shadow-sm">
      <div className="card-body">
        <h1 className="card-title">Endpoints</h1>
        <p className="text-base-content/70">
          No endpoints yet. An endpoint is a SMART authorization server bound to
          one FHIR base URL.
        </p>
      </div>
    </div>
  );
}

/** Application root: providers plus the shared shell. */
export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppShell
        title="Console"
        navigation={
          <>
            <li>
              <a className="active" href="/console">
                Endpoints
              </a>
            </li>
            <li>
              <a href="/console/clients">Clients</a>
            </li>
            <li>
              <a href="/console/policies">Policies</a>
            </li>
            <li>
              <a href="/console/audit">Audit</a>
            </li>
          </>
        }
      >
        <ConsoleHome />
      </AppShell>
    </QueryClientProvider>
  );
}
