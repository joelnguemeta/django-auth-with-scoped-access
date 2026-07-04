# Conformance suite

Implementation-agnostic test cases for the Scoped Access specification (see [SPEC.md](../SPEC.md), §12). Every implementation (Django, Spring Boot, …) MUST pass all cases in `cases/` to claim conformance with the spec version it targets.

## How an implementation consumes these cases

Each implementation ships an **adapter** responsible for:

1. Loading a case file and applying its `config` (hierarchy, role owner levels, grantable-permissions policy).
2. Materializing `nodes`, `roles`, `principals` (with their assignments) and `resources` onto its own models/storage. Fixture `id`s are symbolic — the adapter maps them to real identifiers.
3. Freezing the clock at `now` for all effectiveness evaluations.
4. Running every entry in `checks` against its public API and asserting the `expect` value.

`note` fields are documentation only. Check types are defined in SPEC §12.1.

## Rules

- Cases are **append-only** within a spec minor version; changing the expected behaviour of an existing check requires a spec major bump.
- A new normative rule in SPEC.md MUST land together with at least one covering check ("spec before code").

## Current cases

| File | Covers |
|---|---|
| `cases/coverage.json` | Inclusive subtree coverage, no upward coverage, root scope, global resources, collection filtering (SPEC §4–§5) |
| `cases/lifecycle.json` | Validity windows, suspension, revocation, inactive principal, superuser order (SPEC §5, §8) |
| `cases/tenancy.json` | Custom-role visibility, subtree assignability, anti-escalation (SPEC §6) |
| `cases/flat-rbac.json` | Empty hierarchy = plain RBAC degradation (SPEC §1) |
| `cases/write-guard.json` | Scope-only write admission, unresolvable-anchor deny (SPEC §4.1, §5) |
| `cases/reauth.json` | Step-up token flow: single-use, principal-bound, TTL, bulk invalidation (SPEC §7, §12.1.1) |
| `cases/access-summary.json` | Effective-only introspection content (SPEC §10) |

Not yet covered (needs cases before implementation): duplicate prevention (§8.3), lifecycle events emission (§9).
