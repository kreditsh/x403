# Security

## Reporting

Email security@kredit.sh with the details. Do not open a public issue for a vulnerability. You will get an acknowledgement within two business days and a fix or a plan within fourteen.

## What is in scope

The spec, the schemas, the registry, the test vectors and both packages: anything that lets a decision be replayed, relayed to another executor, laundered onto another payment, forged, or read where it should not be; anything that lets an outcome be posted by a party that may not; anything that turns a timeout into an allow.

## What the protocol relies on

- ES256 over the RFC 8785 canonical form. A signature covers the whole object; a changed field is a different payload.
- Keys published at the well-known documents. Retired keys stay published so old objects still verify; a compromised key is listed with `revoked_at`.
- `audience` and `subject` inside the decision signature. Verifiers check both.
- `on_timeout` is never an allow. A local decision is signed by the executor, never the authority.
- Single-use decisions, nonces and idempotency keys against replay.
- No signed object is cached: `Cache-Control: no-store` on every response that carries one.

## Test keys

The keys in `test-vectors/keys.json` are test keys. They sign nothing outside that directory and must never be used for anything else.
