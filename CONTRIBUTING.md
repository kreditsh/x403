# Contributing

## Before a pull request

- The spec, the schemas, the registry and the test vectors are normative. Change those first; the packages follow.
- Run both suites: `cd packages/typescript && npm test` and `cd packages/python && .venv/bin/pytest -q`. Both read `test-vectors/expectations.json` and must pass every case.
- If an object changed, regenerate the vectors: `packages/python/.venv/bin/python test-vectors/make.py`, and bump the protocol version.
- If the registry changed, run `npm run sync` in `packages/typescript` and copy `registry/reason-codes.json` into `packages/python/src/x403/`.

## Adding a reason code

One entry in `registry/reason-codes.json`: a `group` that exists, an `effect` (`denied`, `escalated` with its `escalation` kind, or `note`), and one sentence in `says`. No weights, no numbers.

## Adding a binding or a profile

Open an issue first. A binding goes in `spec/extensions.md`; a profile for a rail goes under `profiles/` only once something runs end to end against it, and under `profiles/drafts/` before that.

## Style

Plain words, short sentences. No vendor in a normative sentence. No numeric risk value anywhere in an object.
