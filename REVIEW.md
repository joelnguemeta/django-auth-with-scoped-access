# Review guide

What matters when reviewing a change to this repository — for humans and AI reviewers alike.
Read [`AGENTS.md`](AGENTS.md) for the settled architecture; do not re-open those decisions in review.

## What failure looks like here

This is an authorization library. A bug is not a crash, it is **someone seeing or doing what they should not**:

- **Tenant leak** — a user reads or writes a resource outside the subtree their assignment covers.
- **Privilege escalation** — a delegated admin grants a permission they do not hold in that scope (SPEC §6).
- **Stale access** — a revoked, suspended or expired assignment still grants anything (SPEC §8, §11).
- **Fail-open** — an unresolved anchor, missing config or unexpected `None` ends up as *allow* instead of *deny*.
- **Silent audit gap** — a grant/revoke/permission change happens without emitting its §9 signal.
- **Spec drift** — Python behaviour diverges from `SPEC.md` or the conformance cases (a future Java implementation must pass the same suite).

## Always flag

- Authorization logic changed without a matching `SPEC.md` change **and** a conformance case in `conformance/cases/`.
- An existing conformance check edited or removed (cases are append-only within a minor version — SPEC §12.2).
- Views or permission classes testing **role names** instead of permissions.
- A hard-delete of an assignment, or `permissions.add()` / `objects.create()` used to grant (bypasses signals).
- Expiry evaluated anywhere other than at read time (no cron, no stored "expired" flag).
- A cache that survives the request without invalidation through the §9 signals.
- `engine.py` importing DRF, or the core importing `reauth/` / `drf/`.
- ReAuth tokens that become reusable, outlive their TTL, or exempt superusers.
- New queries in a loop (N+1) on assignment/role lookups.
- Migrations missing or depending on host models (scope references are GenericForeignKeys).

## Skip

- `migrations/` content (CI runs `makemigrations --check`), `uv.lock`, `dist/`, `site/`.
- Formatting and import order — ruff owns it.
- Style nits: at most **three** per review, labelled `Nit`.

## Evidence

- Cite `file:line` for every finding. Do not infer behaviour from a function name — read it.
- For a claimed bypass, name the concrete inputs: hierarchy, assignment, resource, expected vs actual decision.
- Mark issues that predate the PR as `Pre-existing`, not as the author's.

## Summary format

Start with the count: `2 important, 1 nit` — or `Nothing to fix.` when that is the case.
