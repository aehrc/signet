/**
 * The append-only audit log: what Signet can record, and how it is written.
 *
 * The module's guarantee is that everything reaching `audit_events.detail` has
 * been through {@link redactAuditDetail}. Nothing here exports a way to insert a
 * row without it.
 *
 * Author: John Grimes
 */

export {
  AUDIT_ACTION_CATEGORIES,
  AUDIT_ACTION_DESCRIPTIONS,
  AUDIT_ACTIONS,
  AUDIT_ACTOR_TYPE_FROM_COLUMN,
  AUDIT_ACTOR_TYPE_TO_COLUMN,
  AUDIT_ACTOR_TYPES,
  AUDIT_TARGET_TYPES,
  isAuditAction,
  isAuditTargetType,
  type AuditAction,
  type AuditActionCategory,
  type AuditActor,
  type AuditActorType,
  type AuditActorTypeColumn,
  type AuditEventInput,
  type AuditEventRecord,
  type AuditTarget,
  type AuditTargetType,
} from "./events.js";

export {
  CYCLE_MARKER,
  isSensitiveKey,
  REDACTED_KEY_EXACT,
  REDACTED_KEY_SUBSTRINGS,
  REDACTED_MARKER,
  redactAuditDetail,
  redactAuditText,
  TRUNCATED_MARKER,
  UNSUPPORTED_MARKER,
} from "./redact.js";

export {
  AUDIT_DETAIL_RESERVED_KEYS,
  auditEventCursorOf,
  buildAuditEventPredicate,
  buildAuditEventRow,
  createAuditRecorder,
  DEFAULT_AUDIT_PAGE_SIZE,
  MAX_AUDIT_PAGE_SIZE,
  normaliseAuditPageSize,
  queryAuditEvents,
  recordAuditEvent,
  toAuditEventRecord,
  type AuditEventCursor,
  type AuditEventFilter,
  type AuditEventOrder,
  type AuditEventPage,
  type AuditFailureReporter,
  type AuditRecordFailure,
  type AuditRecorder,
} from "./record.js";
