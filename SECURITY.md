# Security policy

Signet is an authorization server for clinical data, so we take reports of
vulnerabilities in it seriously. This document explains which versions receive
security fixes, how to report a vulnerability, and what to expect once you have
done so.

## Supported versions

Signet follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Security fixes are applied to the most recent release, and to `main`. Older
releases do not receive backported fixes; if you are affected by a vulnerability,
the recommended remediation is to upgrade to the latest release.

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue,
pull request or discussion for a suspected vulnerability, as this can put other
users at risk before a fix is available.

There are two ways to report:

- **GitHub private vulnerability reporting (preferred).** Use the
  [Report a vulnerability](https://github.com/aehrc/signet/security/advisories/new)
  form to open a private security advisory. This keeps the report, our responses
  and any draft fix in one place.
- **Email.** If you cannot use GitHub, send the details to
  [pathling@csiro.au](mailto:pathling@csiro.au).

Please include as much of the following as you can, so we can reproduce and
assess the issue quickly:

- A description of the vulnerability and the impact you believe it has - for
  example, a token minted with a claim the policy did not grant, a read across a
  tenant boundary, or a credential reaching the audit trail in plaintext.
- The affected component and version, or the commit on `main`.
- Step-by-step instructions to reproduce the issue, including any endpoint,
  policy or client configuration and the requests required.
- Any proof-of-concept code, logs or screenshots.
- Your assessment of severity, if you have one.

## What to expect

- We will acknowledge your report within five business days.
- We will work with you to confirm the issue and determine its severity and
  scope.
- We will keep you informed of our progress towards a fix.
- Once a fix is released, we will publish a security advisory and credit you for
  the discovery, unless you ask to remain anonymous.

We ask that you give us a reasonable opportunity to release a fix before
disclosing the vulnerability publicly. We are happy to coordinate the timing of
public disclosure with you.

## Scope

This policy covers the code maintained in this repository: the server, the web
console and end-user pages, the shared packages, the container image and the
Helm chart.

Vulnerabilities in third-party dependencies are best reported to the relevant
upstream project. If a dependency vulnerability affects Signet and requires a
change on our side (for example, a version bump or a configuration change),
please let us know so that we can address it.

Signet is experimental software, provided without warranty under the
[Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0). It
has not been independently security reviewed and must not be used to protect
sensitive data. See the disclaimer in the [README](README.md).
