# Changelog

Package releases of `@kredit/x403` (npm) and `x403` (PyPI). The protocol version is the `version` field of every object and is listed with each release; it changes only when an object changes.

## 0.2.2 (tag `v0.2.2`, 2026-10-25), protocol 0.1

PyPI only. The npm package did not change and stays at 0.2.0.

- Decisions are states, not commands: `allowed`, `escalated`, `denied` (the first releases said `allow`, `escalate`, `deny`).
- Registry effects are `denied`, `escalated`, `note`; `on_timeout` is `denied`, `escalated` or `allowed_flagged`.
- Every object writes `"version": "0.1"`, the protocol as published.
- This file, and a versions table in the README.
- PyPI 0.2.1 (same day) wrote `0.2` in the `version` field by mistake; use 0.2.2.

## 0.2.0 (2026-10-21), protocol 0.1

- The state words, first release.

## 0.1.2 npm, 0.1.1 PyPI (2026-10-20), protocol 0.1

The first published draft.

- Risk query, decision, receipt, outcome, policy and authority objects; canonical JSON; ES256 detached signatures; the HTTP binding with `X403-Required`, `X403-Presentation` and `X403-Decision`; the reason-code registry; Express, Cloudflare Worker and FastAPI middleware; clients for TypeScript and Python.
