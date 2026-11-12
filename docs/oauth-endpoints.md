# OAuth and OpenID Connect endpoints

An endpoint is one of two kinds, chosen when it is created and fixed from then on.
A **SMART on FHIR** endpoint sits in front of a FHIR server and speaks SMART App
Launch. An **OAuth / OpenID Connect** endpoint is for everything else: it signs
people in to a web app with OpenID Connect, and issues access tokens for an API
that has its own scopes. Nothing about it assumes FHIR.

Both kinds share the rest of Signet: local accounts and federated sign-in, signing
keys with rotation, policies edited and simulated in the console, consent, the
developer portal, introspection, revocation and the audit trail.

## Creating one

Console → **Endpoints** → _New endpoint_, and choose **OAuth / OpenID Connect**.
Through the admin API, name the kind and the audience:

```http
POST /api/v1/tenants/{tenant}/endpoints
Content-Type: application/json

{
  "slug": "notes",
  "name": "Notes",
  "kind": "oauth",
  "audience": "https://notes.example.org/api",
  "supportsBackendServices": true
}
```

The issuer is `{SIGNET_PUBLIC_URL}/t/{tenant}/e/{slug}`, the same shape as a SMART
endpoint's. A new OAuth endpoint is given the **OAuth / OpenID Connect baseline**
policy.

## What differs from a SMART endpoint

### Audience

The endpoint has one audience, an absolute URI that is conventionally the base URL
of the API it protects. Every access token it mints carries it as `aud`, and that
is what the API checks.

A client does not have to name it. If one does - `resource` (RFC 8707) or `aud` on
`/authorize`, `resource` on `/token` - the value must equal the endpoint's audience
or the request is refused with `invalid_target`. An endpoint never mints a token
for an API it does not protect. To protect several APIs, create an endpoint for
each.

A SMART endpoint is unchanged: its audience is the FHIR base URL, and `aud` stays
required on `/authorize`.

### Scopes are opaque, and refused until a rule names them

Any scope token RFC 6749 permits is valid: `notes:read`, `read`, `api.write`. Signet
gives meaning to four of them. `openid`, `profile` and `email` are the OpenID
Connect identity scopes, and `offline_access` asks for a refresh token. Every other
scope is an opaque string, compared for exact equality. That includes strings that
look like SMART scopes, such as `patient/Observation.rs`: on this kind of endpoint
they are just strings.

The baseline policy grants the four and nothing else. An API scope is refused until
the operator adds a grant rule that names it exactly. There are no wildcards. This
is the deny-by-default rule Signet applies everywhere: forgetting to add a rule
produces a refused request, never an unintended grant.

```json
{
  "id": "grant-notes-read",
  "description": "Read your notes.",
  "match": "notes:read",
  "allow": true,
  "grantTypes": ["client_credentials"]
}
```

A rule can be narrowed by grant type, client type and the user's roles, like any
other grant rule. Launch context does not exist here, so a rule cannot
require it.

The consent screen describes each identity scope in words ("Confirm who you are",
"Know your email address"). An API scope is described by the description of the
rule that granted it, and by the scope itself when the rule has none. That makes
a grant rule's description end-user copy on this kind of endpoint, and the
console's rule editor says so.

A client's scope allowlist is checked against the same grammar: an entry that is
not an RFC 6749 scope-token is refused when the client is registered or edited.

### Identity claims

The ID token and userinfo carry:

| Scope     | Claims                                                         |
| --------- | -------------------------------------------------------------- |
| `openid`  | `sub`                                                          |
| `profile` | `name` (the display name), `preferred_username` (the username) |
| `email`   | `email` and `email_verified`, when the user has an email       |

An end user's email and its verified flag are set in the console. Changing or
clearing the email withdraws the verified flag unless the same edit sets it again,
so a flag set for one address never carries over to the next. A federated
sign-in sets the email from the upstream claim mapped to `email`, and sets
`email_verified` only when the upstream provider asserted `email_verified: true`.
An invitation works as it does on a SMART endpoint, and the console starts its
email to the account's recorded address.

There is no `fhirUser`, and roles are not added to the ID token. Roles reach an API
the same way they do on a SMART endpoint: through a claim rule on the access token.

### Discovery

The endpoint serves `{iss}/.well-known/openid-configuration` and answers
`{iss}/.well-known/smart-configuration` with 404.

### What is not available

- EHR launch, `/launch-context`, a client's launch URI and the console's launch
  simulator.
- The patient and encounter picker, and persona launch context. Personas still
  work on non-production endpoints.
- Permission tickets and token exchange.
- The SMART presets, the HAPI interceptor generator and the SMART capability flags.

The client credentials grant is available, under the same capability flag as
SMART Backend Services; the console labels it "Client credentials" here.

## Worked example: oauth2-proxy in front of a web app

The compose stack the end-to-end suite runs against includes one. A static page
and a JSON document, served by nginx, stand for a web app and its API.
[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/), unmodified, stands in
front of both. Nothing in the app knows about OAuth.

`scripts/seedStack.mjs` creates the `notes` endpoint, with the audience
`http://localhost:4180/api`, and on it:

- the baseline policy plus the `grant-notes-read` rule above;
- `notes-proxy`, a confidential client that oauth2-proxy signs people in as,
  allowed `openid profile email`;
- `notes-service`, a confidential client allowed `notes:read` by the client
  credentials grant;
- `nora`, a local account with a verified email address.

oauth2-proxy is configured in `deploy/compose/docker-compose.yml`. The settings
that matter:

```text
--provider=oidc
--oidc-issuer-url=http://localhost:3000/t/demo/e/notes
--client-id=notes-proxy
--client-secret=...
--redirect-url=http://localhost:4180/oauth2/callback
--scope=openid profile email
--code-challenge-method=S256
--skip-jwt-bearer-tokens=true
--extra-jwt-issuers=http://localhost:3000/t/demo/e/notes=http://localhost:4180/api
--bearer-token-login-fallback=false
--api-route=^/api/
```

oauth2-proxy finds everything else from the discovery document. It verifies a
signed-in person's ID token, and refuses an email that is not verified, so
`email_verified` has to be true for the sign-in to complete. `--extra-jwt-issuers`
tells it to accept a bearer token from the endpoint whose `aud` is the API's
audience. `--bearer-token-login-fallback=false` turns a bad token into a 403 rather
than a redirect to sign in, and `--api-route` answers an unauthenticated API
request with 401.

oauth2-proxy has to reach Signet at the same issuer URL the browser uses, because
issuers are compared as exact strings. In the stack it shares Signet's network
namespace, for the same reason Pathling does.

`e2e/tests/oauth.spec.ts` proves the arrangement:

- A browser visiting the app is sent to Signet, signs in as `nora`, consents, and
  lands on the app, which shows the email oauth2-proxy passed upstream.
- An API request with no token is refused with 401.
- A `notes:read` token from the client credentials grant is accepted by
  oauth2-proxy, which passes the token's subject upstream.
- A valid token from the SMART endpoint on the same Signet is refused with 403,
  because its issuer and audience are not the API's.
- A token request naming another `resource` is refused with `invalid_target`, and
  one asking for a scope no rule names is refused with `invalid_scope`.
- The endpoint serves OpenID Connect discovery and no SMART configuration.

```sh
bun run stack:up
cd e2e && bunx playwright test tests/oauth.spec.ts
bun run stack:down
```

## Validating tokens in your own API

An API needs three values: the JWKS URL (`{iss}/jwks`, also `jwks_uri` in the
discovery document), the issuer and the audience. With
[jose](https://github.com/panva/jose):

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const issuer = "https://signet.example.org/t/acme/e/notes";
const audience = "https://notes.example.org/api";
const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks`));

export async function authorize(header: string | undefined): Promise<string> {
  const token = header?.replace(/^Bearer /, "");
  if (token === undefined) {
    throw new Error("No bearer token");
  }
  const { payload } = await jwtVerify(token, jwks, { issuer, audience });
  const scopes = String(payload["scope"] ?? "").split(" ");
  if (!scopes.includes("notes:read")) {
    throw new Error("Missing scope notes:read");
  }
  return payload.sub ?? "";
}
```

`jwtVerify` checks the signature against the endpoint's published keys, and the
issuer, audience and expiry. Fetching the keys from the JWKS URL rather than
pinning them is what lets the endpoint rotate its signing key without a
redeployment of the API. Check the scope your API requires as well: a token that is
valid for the audience is not necessarily one that may do everything there.
