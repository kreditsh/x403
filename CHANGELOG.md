# Changelog

The protocol version is the `version` field of every x403 object. Each entry names the git tag and the SDK releases that speak it.

## 0.2 (tag `v0.2.1`, 2026-10-25)

Protocol 0.2. SDKs: `@kredit/x403` 0.2.1 on npm, `x403` 0.2.1 on PyPI.

- Decisions are states, not commands: `allowed`, `escalated`, `denied` (0.1 said `allow`, `escalate`, `deny`).
- Registry effects are `denied`, `escalated`, `note`; `on_timeout` is `denied`, `escalated` or `allowed_flagged`.
- Every object, the registry and the authority document carry `"version": "0.2"`. The query schema accepts `0.1` and `0.2`, so 0.1 clients are still answered.
- Package 0.2.0 (2026-10-21) already used the state words but wrote `0.1` in the `version` field. 0.2.1 corrects the field and adds this file and the versions table in the README.

## 0.1 (2026-10-20)

Protocol 0.1, the first published draft. SDKs: `@kredit/x403` 0.1.2, `x403` 0.1.1.

- Risk query, decision, receipt, outcome, policy and authority objects; canonical JSON; ES256 detached signatures; the HTTP binding with `X403-Required`, `X403-Presentation` and `X403-Decision`; the reason-code registry; Express, Cloudflare Worker and FastAPI middleware; clients for TypeScript and Python.
