# x403

**A risk decision before money moves.**

x401 says who is asking. x402 says how to pay. x403 is the question in between: the party about to move money asks a risk authority, gets back a signed `allowed`, `escalated` or `denied` with reasons from a shared registry, and both sides keep a receipt anyone can verify offline. After the money moves, the executor reports what happened.

- **Spec:** [`spec/x403.md`](spec/x403.md)
- **Schemas:** [`schemas/`](schemas/) (JSON Schema 2020-12, one file per object)
- **Reason codes:** [`registry/reason-codes.json`](registry/reason-codes.json)
- **TypeScript:** [`packages/typescript`](packages/typescript), `npm install @kredit/x403`
- **Python:** [`packages/python`](packages/python), `pip install x403`
- **Reference authority:** kredit, `https://api.kredit.sh/.well-known/x403/authority.json`
- **Read it rendered:** https://kredit.sh/x403

## In sixty seconds

```ts
import { X403 } from "@kredit/x403";

const x403 = new X403({ authority: "https://api.kredit.sh", apiKey: process.env.KREDIT_API_KEY });

const decision = await x403.decide({
  direction: "inbound",
  payment: { type: "payment", amount: "189.00", currency: "USD", rail: "card", executor: { id: "shop.example" } },
  actor: { agent: { status: "asserted", id: "did:key:z6Mk…" } },
  evidence: [{ type: "kredit.passport", ref: "sha256:…", inline: passport }],
  budget_ms: 150,
});

if (decision.decision === "allowed") charge(decision.constraints);
else respond(decision.http_status, { "X403-Decision": X403.encode(decision) });
```

```python
from x403 import X403

x403 = X403(authority="https://api.kredit.sh", api_key=os.environ["KREDIT_API_KEY"])
decision = x403.decide(direction="outbound", payment={...}, actor={...}, budget_ms=150)
assert x403.verify(decision)  # offline, against the authority's published key
```

## Status codes

Six are normative for clients. The decision carries `http_status`, so no client computes the mapping itself.

| Decision | Status |
| --- | --- |
| allowed | 200 |
| escalated, agent adjusts | 403 |
| escalated, operator or human steps up | 428 |
| denied, identity | 401 |
| denied, compliance | 451 |
| denied, velocity | 429 |
| denied, anything else | 403 |

The full table, with 400, 404 and 409, is in the spec, section 6.3.

## Repository layout

```
spec/        the protocol document
schemas/     JSON Schemas for query, decision, receipt, outcome, policy, authority
registry/    reason codes: group, check, status, default effect
packages/    @kredit/x403 (TypeScript) and x403 (Python): objects, canonical JSON, signing, verifying, middleware
examples/    an Express checkout, a Cloudflare Worker, a FastAPI merchant, a wallet that preflights
```

## Contributing

Reason codes are added by pull request to the registry with a group, an effect and one sentence. Objects change by minor version only. Open an issue before adding a binding.

## License

Apache-2.0. See [LICENSE](LICENSE).
