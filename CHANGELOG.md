# Changelog

Package releases of `@kredit/x403` (npm) and `x403` (PyPI). The protocol version is the `version` field of every object and is listed with each release; it changes only when an object changes.

## 0.3.0 (tag `v0.3.0`, 2026-10-26), protocol 0.2

The objects changed, so the protocol is 0.2. Authorities still answer 0.1 queries; 0.1 decisions still verify.

- **Bound decisions.** `subject` (`payment_ref`, `amount`, `currency`, `executor_id`), `audience` and `query_ref` inside the decision signature. `verifyDecision` / `verify_decision` take the executor's id and the payment and refuse a decision for another executor (`audience_mismatch`) or another payment (`subject_mismatch`).
- **No allow on timeout.** `on_timeout` is `denied` or `escalated`; `allowed_flagged` is gone from the schema, the SDK types and the middleware.
- **Local decisions.** `schemas/local_decision.json`, `localDecision` / `local_decision`, `signLocalDecision`, `verifyLocalDecision`. The middlewares sign one with the executor's key on timeout (`executor`, `privateJwk` / `private_jwk` options) and the authority files it as a receipt (`local_decision` on the receipt).
- **Outcomes.** `decision_hash`, `authority_id`, `category`, `reported_via`; `sig` required on the wire; the authority accepts reports only from the receipt's executor, the requester, itself and registered reporters.
- **Hashes.** x403 hashes are `sha256:`; foreign hashes travel verbatim in `ap2_checkout_hash` and `vi_transaction_id`; `cart_ref` and `payment_requirements_ref` replace `cart_hash` and `payment_requirements_hash`, which are still read.
- **Objects.** `binding_hints.http_status` replaces top-level `http_status` (still read); `latency_ms` removed; `supersedes` is a hash; `revoked.json` lists hashes.
- **Headers.** `Cache-Control: no-store` on every response that carries an x403 header; a header value over 8 KB is refused (`MAX_HEADER_BYTES`); `application/x403+json` for bodies.
- **Registry.** `audience_mismatch`, `subject_mismatch`, `presentation_signature_invalid` (400); `superseded_by_review` is 409; `action_not_granted`, `action_outside_tools`, `agent_unpublished` retired.
- **Repo.** `test-vectors/` with fixed keys and negative cases, read by both suites; `GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODEOWNERS`; spec sections for terminology (1.1), the local decision (4.6) and security considerations (12).

## 0.2.2 (tag `v0.2.2`, 2026-10-25), protocol 0.1

PyPI only. The npm package did not change and stayed at 0.2.0.

- Decisions are states, not commands: `allowed`, `escalated`, `denied` (the first releases said `allow`, `escalate`, `deny`).
- Registry effects are `denied`, `escalated`, `note`; `on_timeout` is `denied`, `escalated` or `allowed_flagged`.
- Every object writes `"version": "0.1"`, the protocol as published.
- PyPI 0.2.1 (same day) wrote `0.2` in the `version` field by mistake; use 0.2.2.

## 0.2.0 (2026-10-21), protocol 0.1

- The state words, first release.

## 0.1.2 npm, 0.1.1 PyPI (2026-10-20), protocol 0.1

The first published draft.

- Risk query, decision, receipt, outcome, policy and authority objects; canonical JSON; ES256 signatures; the HTTP binding with `X403-Required`, `X403-Presentation` and `X403-Decision`; the reason-code registry; Express, Cloudflare Worker and FastAPI middleware; clients for TypeScript and Python.
