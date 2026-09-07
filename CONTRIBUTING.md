# Contributing to Signet

Contributions are welcome. This document says what to expect and what a change
has to satisfy to be merged.

## Code of conduct

This project adheres to the [Contributor Covenant Code of
Conduct](CODE_OF_CONDUCT.md). By participating you are expected to uphold it.
Report unacceptable behaviour to pathling@csiro.au.

## Reporting bugs

Check the existing issues first. A useful report includes:

- A clear, descriptive title.
- The steps that produce the behaviour, including the endpoint, grant type and
  scopes involved where the report is about a request Signet refused or a token
  it minted.
- What you expected, and what happened.
- The Signet version or commit, and how it is running (`overmind`, the compose
  stack, the container image, the Helm chart).
- The relevant server log lines, with credentials removed.

A security vulnerability is not a GitHub issue. Report it privately as described
in [SECURITY.md](SECURITY.md), and give us a chance to release a fix before
disclosing it.

## Suggesting enhancements

Say what the change would let somebody do that they cannot do now, and why the
existing mechanisms do not cover it. A new claims-mapping capability is usually
better argued as a policy rule than as code, so name the rule you would want to
write.

A preset for a resource server needs a citation. Presets are written from the
server's published documentation, or from its source where the documentation
does not say; see `docs/resource-servers.md` for the standard each existing
preset was held to.

## Pull requests

1. Fork the repository and branch from `main`.
2. Write the tests first. Test-driven development is a project principle, not a
   preference - see the constitution in [CLAUDE.md](CLAUDE.md).
3. Open the pull request as a draft until it is ready for review.
4. Keep commits atomic, in the imperative mood, with a subject line of 50
   characters or fewer.
5. Reference the issue the change closes.

CI must be green before merge, and the gates are not to be weakened to make a
change pass. See "Quality gates" in [CLAUDE.md](CLAUDE.md).

## Development setup

Requires [Bun](https://bun.sh) and Docker.

```sh
bun install
cp .env.example .env.test               # the test database, for `bun run test`
cp apps/server/.env.example apps/server/.env.local
cp packages/db/.env.example packages/db/.env.local
overmind start                          # server on :3000, console on :5173
```

The three `.env.example` files each say which of their variables belongs in which
file, and why. The compose stack's ports (`SIGNET_PORT`, `PATHLING_PORT`,
`APP_PORT`) are the exception: they must be exported into the shell rather than
written to a file, because Bun does not pass variables it loaded from a file to
the processes it launches. The root `.env.example` explains this.

## Coding standards

The project's non-negotiable principles are in [CLAUDE.md](CLAUDE.md). The ones
a first contribution most often runs into:

- **Logic lives in `packages/core`,** as functions with no I/O. The server and
  the web console compose those functions rather than re-implementing them, so
  that the console's policy simulator and the token issuer cannot disagree.
- **No classes.** Behaviour is standalone functions over plain data. The `class`
  keyword is permitted only where the language gives no alternative - an `Error`
  subclass, a React error boundary.
- **Tenant-owned data is reached only through the repositories** in
  `packages/db/src/repositories/`, which demand a scope value that cannot be
  constructed by hand, and every tenant-owned table carries a row-level security
  policy added in the migration that creates the table.
- **Deny by default.** New capability is reachable by adding a rule, never by
  removing a restriction.
- Every exported function carries a JSDoc comment. Australian English, in
  prose and in identifiers.
- Files are named in lower camel case, except React components, which are
  Pascal case.

Formatting is Prettier with its defaults, and it is checked in CI:

```sh
bun run format         # write
bun run format:check   # check, as CI does
bun run lint
bun run typecheck
bun run lint:duplication
```

## Testing

```sh
bun run test           # unit and integration tests
bun run test:coverage  # with the coverage floor CI enforces
```

Integration suites skip themselves when `SIGNET_TEST_DATABASE_URL` is unset, and
the run still reports success. A `bun run test` that finishes in a couple of
seconds with a `skip` count has not exercised the database. Point the variable
at a throwaway database.

The end-to-end suite drives a real SMART launch in a browser against a
docker-compose stack of Signet, a FHIR server and a stub app:

```sh
bun run stack:up
bun run stack:seed
bun run test:e2e
bun run stack:down
```

A second Playwright project, `mobile`, runs `e2e/tests/responsive.spec.ts` at a
360px viewport and asserts the narrow-viewport rendering rather than leaving it to
inspection:

```sh
cd e2e && bunx playwright test responsive --project=mobile
```

End-user sign-ins are rate limited to ten a minute per address, and a full run
spends most of that, so leave a minute between runs.

## Legal

### Developer Certificate of Origin

This project uses the Developer Certificate of Origin (DCO) rather than a
Contributor Licence Agreement. By signing off a commit you certify that you have
the right to submit that contribution to this project, and that it may be
distributed under the project's Apache License 2.0.

Sign off each commit:

```sh
git commit -s
```

That adds a line of the form:

```
Signed-off-by: Jane Smith <jane@example.com>
```

The full text of the DCO is at <https://developercertificate.org/>.

### Licensing

By contributing to Signet you agree that your contribution is licensed under the
Apache License 2.0 along with the rest of the project. Contributors retain
copyright in their own work unless otherwise agreed.

### Third-party code and dependencies

Submit only code that you wrote yourself, or that you are authorised to
contribute. Where a contribution includes or is derived from third-party code, or
introduces a new dependency, identify its source and licence in the pull request.
Material under a licence incompatible with the Apache License 2.0 cannot be
accepted.

Where a contribution requires changes to attribution or notice files, include
those changes in the same pull request.

### AI-assisted development

AI-assisted development tools may be used in preparing a contribution. The
contributor remains responsible for reviewing all generated code, for holding the
right to contribute it, and for its compliance with this project's licensing and
quality requirements.
