// A merchant checkout on Express: ask kredit before charging, charge within the
// constraints, countersign the receipt, report the outcome when the card settles.
import express from "express";
import { X403, generateKey } from "@kredit/x403";
import { x403, receipt } from "@kredit/x403/express";

const authority = new X403({ authority: "https://api.kredit.sh", apiKey: process.env.KREDIT_API_KEY });
// In production the key is loaded, not generated, and its public half is served at
// /.well-known/x403/jwks.json so a dispute desk can verify the receipts offline.
const { privateJwk, publicJwk, kid } = await generateKey();

const app = express();
app.use(express.json());
app.get("/.well-known/x403/jwks.json", (_req, res) => res.json({ keys: [publicJwk] }));

const gate = x403({
  client: authority,
  policyId: "shop-checkout-v1",
  budgetMs: 150,
  onTimeout: "deny",
  payment: (req) => ({
    type: "payment",
    amount: String(req.body.amount),
    currency: "USD",
    rail: "card",
    executor: { id: "shop.example", category: "5732", jurisdiction: "US" },
    items: req.body.items,
    references: { order_id: req.body.order_id },
    idempotency_key: req.body.order_id,
  }),
});

const postReceipt = receipt({ client: authority });

app.post("/checkout", gate, async (req, res) => {
  const decision = req.x403!;
  // The yes is scoped: a ceiling, a step-up line, an expiry. Charge inside it.
  const auth = await charge(req.body, decision.constraints);
  await postReceipt({
    decision,
    executed: true,
    execution: { rail: "card", ref: auth.id, amount: String(req.body.amount), currency: "USD" },
    executor: { id: "did:web:shop.example", kid },
    privateJwk,
  });
  res.json({ ok: true, auth: auth.id, decision: decision.id });
});

// Days later, when the processor says the charge settled or came back.
app.post("/webhooks/processor", async (req, res) => {
  await authority.outcome({
    decision_ref: req.body.decision_id,
    outcome: req.body.event === "settled" ? "settled" : "chargeback",
    at: new Date().toISOString(),
    amount: String(req.body.amount),
    currency: "USD",
    reason_code: req.body.reason_code,
    reporter: { id: "did:web:shop.example", kid },
  });
  res.sendStatus(204);
});

async function charge(body: { amount: number }, constraints?: { max_amount?: string }) {
  if (constraints?.max_amount && body.amount > Number(constraints.max_amount)) throw new Error("above the decision's ceiling");
  return { id: `auth_${Date.now().toString(36)}` };
}

app.listen(3000);
