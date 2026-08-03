/**
 * Console sign-in, sign-out, and "who am I?".
 *
 * The sign-in path is written to give away as little as it can. An unknown email,
 * a wrong password, a disabled account and a missing second factor all produce the
 * same refusal with the same message and the same cost: the password is verified
 * against an unmatchable hash when no account was found, so the response time does
 * not distinguish the cases. What the operator sees is "those credentials were not
 * accepted", which is all a legitimate user needs and all an attacker should get.
 *
 * The one deliberate exception is the second factor. When the password is right and
 * a TOTP code is required but absent, the response says so — with a distinct
 * `totpRequired` flag rather than a different message — because the console has to
 * know to show the field. That does disclose that the password was correct, which
 * is unavoidable in any interface that asks for a second factor on a second screen,
 * and the code itself still has to be right.
 *
 * Sign-in events are recorded in the audit trail of every tenant the account
 * belongs to. `audit_events.tenant_id` is not nullable — deliberately, so that
 * reading a tenant's trail cannot surface another tenant's events — and a console
 * identity is not tenant-scoped, so there is no single tenant to attribute a login
 * to. Writing it to each of them is what makes "who signed in and could have
 * changed my configuration?" answerable from within a tenant. A refused sign-in for
 * an email that resolves to no account has no tenant at all, and so is recorded
 * only in the process log.
 */

import { adminLoginSchema } from "@signet/contracts";
import {
  createAdminSession,
  decryptSecret,
  findAdminUserByEmail,
  generateOpaqueToken,
  hashToken,
  listTenantsForAdminUser,
  recordAdminLogin,
  revokeAdminSession,
  verifyPassword,
  verifyTotp,
} from "@signet/db";

import {
  clearedSessionCookie,
  cookiesAreSecure,
  SESSION_TTL_SECONDS,
  sessionCookie,
} from "./cookies.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { parseBody } from "./requestBody.js";
import { requestMetadata } from "../http/requestMeta.js";
import { logRecord } from "../observability/log.js";
import { UNMATCHABLE_PASSWORD_HASH } from "../security/passwordTiming.js";

import type { AdminPrincipal } from "./principal.js";
import type { ServerContext, SignetEnvironment } from "../context.js";
import type { AdminUser, AuditAction } from "@signet/db";
import type { Context } from "hono";

/** What the console is told about the signed-in person. */
interface SessionView {
  readonly user: {
    readonly id: string;
    readonly email: string;
    readonly displayName: string;
    /** So the security page can offer to enrol rather than to re-enrol. */
    readonly totpEnrolled: boolean;
  };
  readonly tenants: readonly {
    readonly slug: string;
    readonly name: string;
    readonly role: string;
  }[];
}

/**
 * Records a sign-in or a refusal in every tenant the account belongs to.
 *
 * @param context - The server's dependencies.
 * @param metadata - Where the request came from.
 * @param user - The account, when the email resolved to one.
 * @param action - The event to record.
 * @param detail - Anything specific to this attempt. Never a credential.
 */
async function recordAuthenticationEvent(
  context: ServerContext,
  metadata: ReturnType<typeof requestMetadata>,
  user: AdminUser | undefined,
  action: AuditAction,
  detail: Record<string, unknown>,
): Promise<void> {
  // Always logged, whether or not there is a tenant to attribute it to. A
  // deployment watching for password spraying needs the refusals that resolved to
  // no account most of all, and those are exactly the ones with no audit row.
  logRecord(context.config.logLevel, "warn", `signet.${action}`, {
    adminUserId: user?.id ?? null,
    ip: metadata.ip ?? null,
    ...detail,
  });

  if (user === undefined) {
    return;
  }

  const memberships = await listTenantsForAdminUser(context.db, user.id);
  for (const membership of memberships) {
    await context.audit.record(context.db, {
      tenantId: membership.tenant.id,
      actor: { type: "admin-user", id: user.id, displayName: user.displayName },
      action,
      target: { type: "admin-user", id: user.id },
      detail,
      ...metadata,
    });
  }
}

/**
 * Names why a sign-in was refused, for the audit trail only.
 *
 * The caller is told none of this — every refusal returns the same body — so this
 * exists to make the trail useful to the operator reading it afterwards: "disabled
 * account" and "wrong password" call for quite different responses.
 *
 * @param user - The account, when the email resolved to one.
 * @param passwordMatches - Whether the presented password verified.
 */
function signInRefusalReason(
  user: AdminUser | undefined,
  passwordMatches: boolean,
): string {
  if (user === undefined) {
    return "no-such-account";
  }
  if (!passwordMatches) {
    return "password-rejected";
  }
  return "account-disabled";
}

/** The refusal every failed sign-in produces, whatever the reason. */
function refuseSignIn(c: Context<SignetEnvironment>) {
  return c.json(
    adminErrorBody("unauthenticated", "Those credentials were not accepted"),
    statusForAdminError("unauthenticated"),
  );
}

/**
 * Builds the view of a signed-in person and the tenants they may act on.
 *
 * @param context - The server's dependencies.
 * @param user - The signed-in account.
 */
async function sessionView(
  context: ServerContext,
  user: AdminUser,
): Promise<SessionView> {
  const memberships = await listTenantsForAdminUser(context.db, user.id);
  return {
    user: {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      totpEnrolled: user.totpSecretEncrypted !== null,
    },
    tenants: memberships.map((membership) => ({
      slug: membership.tenant.slug,
      name: membership.tenant.name,
      role: membership.role,
    })),
  };
}

/**
 * Verifies an enrolled second factor.
 *
 * The secret is decrypted here and nowhere else in the sign-in path; it is stored
 * envelope-encrypted precisely so that a database disclosure does not hand over
 * every operator's authenticator seed.
 *
 * @param context - The server's dependencies.
 * @param user - The account, whose `totpSecretEncrypted` must be present.
 * @param code - The six digits the operator typed.
 */
async function secondFactorAccepted(
  context: ServerContext,
  user: AdminUser,
  code: string,
): Promise<boolean> {
  if (user.totpSecretEncrypted === null) {
    return true;
  }
  const secret = await decryptSecret(
    user.totpSecretEncrypted,
    context.config.masterKey,
  );
  return verifyTotp(secret, code, Math.floor(context.clock().getTime() / 1000));
}

/**
 * Handles `POST /api/v1/session`: signs in.
 *
 * @param context - The server's dependencies.
 */
export function adminLoginHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const metadata = requestMetadata(c);
    const body = await parseBody(c, adminLoginSchema);
    if (body instanceof Response) {
      return body;
    }

    const user = await findAdminUserByEmail(context.db, body.email);
    // Verified whether or not the account exists, and before the disabled check,
    // so that every refusal costs one Argon2id verification. See the header.
    const passwordMatches = await verifyPassword(
      body.password,
      user?.passwordHash ?? UNMATCHABLE_PASSWORD_HASH,
    );

    if (user === undefined || !passwordMatches || user.disabledAt !== null) {
      await recordAuthenticationEvent(
        context,
        metadata,
        user,
        "admin.login-failed",
        { reason: signInRefusalReason(user, passwordMatches) },
      );
      return refuseSignIn(c);
    }

    if (user.totpSecretEncrypted !== null && body.totp === undefined) {
      // Not a refusal to record: the password was right and nothing has been
      // decided yet. The console shows the code field and posts again.
      return c.json(
        {
          ...adminErrorBody(
            "unauthenticated",
            "This account requires a verification code",
          ),
          totpRequired: true,
        },
        statusForAdminError("unauthenticated"),
      );
    }

    if (!(await secondFactorAccepted(context, user, body.totp ?? ""))) {
      await recordAuthenticationEvent(
        context,
        metadata,
        user,
        "admin.login-failed",
        { reason: "totp-rejected" },
      );
      return refuseSignIn(c);
    }

    const token = generateOpaqueToken();
    await createAdminSession(context.db, {
      adminUserId: user.id,
      tokenHash: await hashToken(token),
      expiresAt: new Date(
        context.clock().getTime() + SESSION_TTL_SECONDS * 1000,
      ),
      ip: metadata.ip ?? null,
      userAgent: metadata.userAgent ?? null,
    });
    await recordAdminLogin(context.db, user.id, context.clock());
    await recordAuthenticationEvent(context, metadata, user, "admin.login", {});

    c.header(
      "Set-Cookie",
      sessionCookie(token, {
        secure: cookiesAreSecure(context.config.publicUrl),
      }),
    );
    // A response that establishes a credential must never be cached, even though
    // the credential itself is in a header rather than in the body.
    c.header("Cache-Control", "no-store");
    return c.json(await sessionView(context, user));
  };
}

/**
 * Handles `DELETE /api/v1/session`: signs out.
 *
 * Revoking is idempotent from the caller's point of view — the cookie is cleared
 * either way — but the data layer distinguishes the two, and only a session that
 * was live produces an audit event.
 *
 * @param context - The server's dependencies.
 */
export function adminLogoutHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal: AdminPrincipal = c.get("principal");
    const metadata = requestMetadata(c);

    if (principal.kind === "admin-user") {
      const revoked = await revokeAdminSession(
        context.db,
        principal.sessionTokenHash,
        context.clock(),
      );
      if (revoked) {
        await recordAuthenticationEvent(
          context,
          metadata,
          principal.user,
          "admin.logout",
          {},
        );
      }
    }

    c.header(
      "Set-Cookie",
      clearedSessionCookie({
        secure: cookiesAreSecure(context.config.publicUrl),
      }),
    );
    return c.body(null, 204);
  };
}

/**
 * Handles `GET /api/v1/session`: reports the signed-in person and their tenants.
 *
 * This is how the console decides what to render before it knows anything else, so
 * it doubles as the check that a stored cookie is still live.
 *
 * @param context - The server's dependencies.
 */
export function adminSessionHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal: AdminPrincipal = c.get("principal");

    if (principal.kind === "api-token") {
      // A token is not a person and has exactly one tenant. Reported in the same
      // shape so a script can use this as its "am I authenticated?" probe.
      return c.json({
        token: {
          id: principal.token.id,
          name: principal.token.name,
          role: principal.role,
        },
        tenants: [
          {
            slug: principal.scope.tenantSlug,
            role: principal.role,
          },
        ],
      });
    }

    return c.json(await sessionView(context, principal.user));
  };
}
