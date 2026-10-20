// The reason-code registry and the status mapping of spec section 6.3. The decision
// carries http_status already; this is for an executor that wants to recompute it, and
// for the tests that pin the table.

import { REGISTRY } from "./reason-codes.js";
import type { CheckKey, Decision, Effect, EscalationKind, HttpStatus, ReasonCodeEntry, Registry } from "./types.js";

export const registry: Registry = REGISTRY as unknown as Registry;

export function entryOf(code: string): ReasonCodeEntry | undefined {
  return registry.codes[code];
}

export function groupOf(code: string): string | undefined {
  return registry.codes[code]?.group;
}

export function checkOf(code: string): CheckKey | undefined {
  const group = groupOf(code);
  return group ? registry.groups[group]?.check : undefined;
}

export function effectOf(code: string): Effect | undefined {
  return registry.codes[code]?.effect;
}

export function escalationOf(code: string): EscalationKind | undefined {
  return registry.codes[code]?.escalation;
}

/** The deny groups in the order section 6.3 consults them, after system codes. */
const DENY_ORDER: Array<[string, HttpStatus]> = [
  ["compliance", 451],
  ["identity", 401],
  ["velocity", 429],
];

/**
 * Section 6.3. allow is 200. escalate is by kind. deny is the status of the first group,
 * in order, that has a code on the decision: a system code with its own status and a deny
 * effect (a note such as shadow_mode never turns a deny into a 200), then compliance,
 * identity, velocity, else 403.
 */
export function statusFor(decision: Pick<Decision, "decision" | "reasons"> & { escalation?: { kind: EscalationKind } }): HttpStatus {
  if (decision.decision === "allow") return 200;
  if (decision.decision === "escalate") {
    const kind = decision.escalation?.kind;
    const byKind = registry.status.escalate;
    return (kind && byKind[kind] ? byKind[kind] : 403) as HttpStatus;
  }
  const reasons = decision.reasons ?? [];
  for (const code of reasons) {
    const entry = registry.codes[code];
    if (entry?.group === "system" && entry.effect === "deny" && entry.status) return entry.status as HttpStatus;
  }
  const groups = new Set(reasons.map((c) => registry.codes[c]?.group).filter(Boolean));
  for (const [group, status] of DENY_ORDER) if (groups.has(group)) return status;
  return 403;
}

/** The six statuses a client must handle; anything else may be treated as 403. */
export const NORMATIVE_STATUSES: readonly HttpStatus[] = [200, 401, 403, 428, 429, 451];
