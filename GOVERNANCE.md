# Governance

x403 is an open protocol with kredit as the reference authority. This file says how it changes.

## What is normative

The spec (`spec/x403.md`), the schemas (`schemas/`), the registry (`registry/`) and the test vectors (`test-vectors/`). The packages implement them; where a package and the spec disagree, the spec is right and the package has a bug.

## How the protocol changes

- An object changes only by pull request against `spec/x403.md` and the schema it affects, with the test vectors regenerated and both packages passing them.
- A change to an object bumps the protocol version (the `version` field). Fields are added in a minor version; a field is never removed or renamed in a minor version, it is marked deprecated and still read for at least one minor version.
- Reason codes are added by pull request to `registry/reason-codes.json` with a group, an effect and one sentence. A code is never removed; a retired code keeps its entry with `"retired": true`.
- Anything that names a vendor is a registry entry or evidence type, never a normative enum in the spec.

## Who decides

The maintainers named in `CODEOWNERS` merge. A change that affects the wire (an object, a header, a status) needs a second maintainer's review and a note in `CHANGELOG.md`. Disagreements are settled in the pull request, in writing.

## Versions

The protocol version is the `version` field of every object. The packages have their own release numbers; the README maps each package release to the protocol version it speaks. Every package release is a git tag and a GitHub release.

## Security reports

See `SECURITY.md`. A security fix may ship before its pull request is public.
