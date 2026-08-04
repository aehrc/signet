/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  AUDIT_ACTION_CATEGORIES,
  AUDIT_ACTION_DESCRIPTIONS,
  AUDIT_ACTIONS,
  AUDIT_ACTOR_TYPE_FROM_COLUMN,
  AUDIT_ACTOR_TYPE_TO_COLUMN,
  AUDIT_ACTOR_TYPES,
  isAuditAction,
  type AuditAction,
} from "./events.js";
import { auditActorTypeEnum } from "../schema/enums.js";

/**
 * Actions the plan requires Signet to be able to record.
 *
 * Listed independently of the vocabulary so that removing one is a failing test
 * rather than a quiet loss of coverage. The union is allowed to grow beyond this
 * list; it is not allowed to shrink below it.
 */
const REQUIRED_ACTIONS: readonly AuditAction[] = [
  "admin.login",
  "admin.login-failed",
  "admin.logout",
  "end-user.login",
  "end-user.login-failed",
  "authorize.requested",
  "authorize.denied",
  "authorize.consented",
  "authorize.code-issued",
  "token.issued",
  "token.denied",
  "token.refreshed",
  "token.refresh-reuse-detected",
  "token.revoked",
  "token.introspected",
  "tenant.created",
  "endpoint.created",
  "endpoint.updated",
  "endpoint.deleted",
  "key.created",
  "key.rotated",
  "key.retired",
  "policy.created",
  "policy.published",
  "client.created",
  "client.updated",
  "client.suspended",
  "client.secret-rotated",
  "client-request.submitted",
  "client-request.approved",
  "client-request.rejected",
  "end-user.created",
  "end-user.updated",
  "end-user.disabled",
];

describe("the audit action vocabulary", () => {
  it.each(REQUIRED_ACTIONS)("includes %s", (action) => {
    expect(AUDIT_ACTIONS).toContain(action);
  });

  it("describes and categorises every action", () => {
    for (const action of AUDIT_ACTIONS) {
      expect(AUDIT_ACTION_DESCRIPTIONS[action]).toBeTruthy();
      expect(AUDIT_ACTION_CATEGORIES[action]).toBeTruthy();
    }

    expect(Object.keys(AUDIT_ACTION_CATEGORIES).toSorted()).toEqual(
      [...AUDIT_ACTIONS].toSorted(),
    );
  });

  it("gives each action a distinct description, so a reader can tell two apart", () => {
    const descriptions = AUDIT_ACTIONS.map(
      (action) => AUDIT_ACTION_DESCRIPTIONS[action],
    );

    expect(new Set(descriptions).size).toBe(descriptions.length);
  });

  it("names actions as subject.verb, lower case and hyphenated", () => {
    for (const action of AUDIT_ACTIONS) {
      expect(action).toMatch(/^[a-z][a-z-]*\.[a-z][a-z-]*$/);
    }
  });

  it("has no duplicate actions", () => {
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
  });

  it("recognises known actions and rejects everything else", () => {
    expect(isAuditAction("token.issued")).toBe(true);
    expect(isAuditAction("token.issud")).toBe(false);
    expect(isAuditAction("")).toBe(false);
    // A row written by a newer deployment must be reported as unknown rather
    // than crash a renderer.
    expect(isAuditAction("something.invented-later")).toBe(false);
  });
});

describe("actor type mapping", () => {
  it("covers exactly the values the Postgres enum allows", () => {
    expect(Object.values(AUDIT_ACTOR_TYPE_TO_COLUMN).toSorted()).toEqual(
      [...auditActorTypeEnum.enumValues].toSorted(),
    );
    expect(Object.keys(AUDIT_ACTOR_TYPE_FROM_COLUMN).toSorted()).toEqual(
      [...auditActorTypeEnum.enumValues].toSorted(),
    );
  });

  it("round-trips every actor type", () => {
    for (const actorType of AUDIT_ACTOR_TYPES) {
      const column = AUDIT_ACTOR_TYPE_TO_COLUMN[actorType];
      expect(AUDIT_ACTOR_TYPE_FROM_COLUMN[column]).toBe(actorType);
    }
  });

  it("lists every actor type once", () => {
    expect(AUDIT_ACTOR_TYPES).toHaveLength(
      auditActorTypeEnum.enumValues.length,
    );
    expect(new Set(AUDIT_ACTOR_TYPES).size).toBe(AUDIT_ACTOR_TYPES.length);
  });
});
