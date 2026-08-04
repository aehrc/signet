/**
 * Structured logging, and the one decision it involves.
 *
 * Signet writes single-line JSON objects to the process's own streams and leaves
 * collection to the platform: a pod's logs are already gathered, and an
 * authorization server that shipped them somewhere itself would be a component
 * with an outbound dependency on the day it is most needed.
 *
 * The only judgement here is whether a message clears the configured threshold,
 * which is pure and therefore tested. Everything security-relevant is emitted at
 * `warn`, so a deployment that sets `SIGNET_LOG_LEVEL=error` is choosing to keep
 * only failures - a legitimate choice for a noisy environment, and the reason the
 * audit trail, which is not suppressible, exists separately.
 *
 * Author: John Grimes
 */

import type { SignetConfig } from "../config.js";

/** Severity of a log record. */
export type LogLevel = SignetConfig["logLevel"];

/** Severities in increasing order, so a threshold is a comparison. */
const LEVEL_RANK: Readonly<Record<LogLevel, number>> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

/**
 * Whether a record at `level` should be emitted under `configured`.
 *
 * @param configured - The deployment's `SIGNET_LOG_LEVEL`.
 * @param level - The severity of the record in hand.
 */
export function shouldLog(configured: LogLevel, level: LogLevel): boolean {
  return LEVEL_RANK[level] >= LEVEL_RANK[configured];
}

/**
 * Emits one structured record, if the threshold permits it.
 *
 * `message` is a dotted event name rather than a sentence, so records can be
 * counted and alerted on without parsing prose.
 *
 * @param configured - The deployment's `SIGNET_LOG_LEVEL`.
 * @param level - The severity of this record.
 * @param message - Dotted event name, e.g. `signet.admin.login-failed`.
 * @param fields - Everything specific to this record. Never a credential.
 */
export function logRecord(
  configured: LogLevel,
  level: LogLevel,
  message: string,
  fields: Readonly<Record<string, unknown>> = {},
): void {
  if (!shouldLog(configured, level)) {
    return;
  }
  const line = JSON.stringify({ level, message, ...fields });
  if (level === "error" || level === "warn") {
    console.error(line);
  } else {
    console.log(line);
  }
}
