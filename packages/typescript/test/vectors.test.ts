// The repo's test vectors: every implementation must give the result expectations.json names.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyDecision, verifyLocalDecision, verifyReceipt } from "../src/jws.js";
import type { Decision, JWK, LocalDecision, Payment, Receipt } from "../src/types.js";

const DIR = fileURLToPath(new URL("../../../test-vectors/", import.meta.url));
const read = <T>(name: string): T => JSON.parse(readFileSync(DIR + name, "utf8")) as T;

interface Case {
  name: string;
  file: string;
  object: "decision" | "local" | "receipt";
  keys: "authority" | "executor";
  audience?: string;
  payment?: string;
  expect: { ok: boolean; reason?: string };
}

const keys = read<{ authority: { public: JWK }; executor: { public: JWK } }>("keys.json");
const cases = read<{ cases: Case[] }>("expectations.json").cases;

describe("test vectors", () => {
  for (const c of cases) {
    it(c.name, async () => {
      const jwk = keys[c.keys].public;
      const options = { audience: c.audience, payment: c.payment ? read<Payment>(c.payment) : undefined, now: new Date("2026-10-25T12:00:00Z") };
      const result =
        c.object === "decision"
          ? await verifyDecision(read<Decision>(c.file), jwk, options)
          : c.object === "local"
            ? await verifyLocalDecision(read<LocalDecision>(c.file), jwk, options)
            : await verifyReceipt(read<Receipt>(c.file), jwk);
      expect(result.ok).toBe(c.expect.ok);
      if (c.expect.reason) expect(result.reason).toBe(c.expect.reason);
    });
  }
});
