import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { checkOf, effectOf, escalationOf, groupOf, registry, statusFor } from "../src/registry.js";

describe("registry", () => {
  it("is the repo registry, unchanged", () => {
    const source = JSON.parse(readFileSync(resolve(__dirname, "../../../registry/reason-codes.json"), "utf8"));
    expect(registry).toEqual(source);
  });

  it("every code belongs to a known group and every escalate names a kind", () => {
    for (const [code, entry] of Object.entries(registry.codes)) {
      expect(registry.groups[entry.group], code).toBeDefined();
      if (entry.effect === "escalate") expect(entry.escalation, code).toBeDefined();
    }
    expect(groupOf("sanctions_hit")).toBe("compliance");
    expect(checkOf("sanctions_hit")).toBe("payee");
    expect(effectOf("amount_over_cap")).toBe("escalate");
    expect(escalationOf("amount_over_cap")).toBe("agent_adjust");
    expect(groupOf("no_such_code")).toBeUndefined();
  });
});

describe("section 6.3", () => {
  const deny = (reasons: string[]) => statusFor({ decision: "deny", reasons });
  const escalate = (kind: "agent_adjust" | "operator_confirm" | "human_stepup" | "executor_review") =>
    statusFor({ decision: "escalate", reasons: [], escalation: { kind } });

  it("allow is 200 with or without constraints", () => {
    expect(statusFor({ decision: "allow", reasons: ["amount_at_cap"] })).toBe(200);
  });

  it("escalate is by kind", () => {
    expect(escalate("agent_adjust")).toBe(403);
    expect(escalate("operator_confirm")).toBe(428);
    expect(escalate("human_stepup")).toBe(428);
    expect(escalate("executor_review")).toBe(403);
    expect(statusFor({ decision: "escalate", reasons: [] })).toBe(403);
  });

  it("deny, identity group is 401", () => {
    expect(deny(["instance_token_expired"])).toBe(401);
    expect(deny(["human_unverified", "amount_over_cap"])).toBe(401);
  });

  it("deny, compliance group is 451, ahead of identity", () => {
    expect(deny(["sanctions_hit"])).toBe(451);
    expect(deny(["agent_frozen", "jurisdiction_blocked"])).toBe(451);
  });

  it("deny, velocity group is 429", () => {
    expect(deny(["velocity_high"])).toBe(429);
    expect(deny(["rate_cap_exceeded", "blocked_counterparty"])).toBe(429);
  });

  it("deny, any other group is 403", () => {
    expect(deny(["blocked_counterparty"])).toBe(403);
    expect(deny(["injection_pattern"])).toBe(403);
    expect(deny(["dispute_history"])).toBe(403);
    expect(deny([])).toBe(403);
  });

  it("replay and expiry are 409", () => {
    for (const code of ["nonce_consumed", "decision_expired", "decision_consumed", "decision_superseded"]) expect(deny([code]), code).toBe(409);
  });

  it("a wrong request is 400", () => {
    for (const code of ["policy_unknown", "presentation_malformed", "evidence_hash_mismatch"]) expect(deny([code]), code).toBe(400);
  });

  it("bad evidence or query signature is 401, timeout is 403", () => {
    expect(deny(["evidence_signature_invalid"])).toBe(401);
    expect(deny(["requester_signature_invalid"])).toBe(401);
    expect(deny(["evidence_expired"])).toBe(401);
    expect(deny(["authority_timeout"])).toBe(403);
  });

  it("a system code wins over the groups, and a system note does not", () => {
    expect(deny(["sanctions_hit", "nonce_consumed"])).toBe(409);
    expect(deny(["shadow_mode", "sanctions_hit"])).toBe(451);
    expect(deny(["evidence_unsupported", "velocity_high"])).toBe(429);
  });
});
