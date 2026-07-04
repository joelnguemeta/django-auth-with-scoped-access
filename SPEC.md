# Scoped Access — Specification

**Version:** 0.1.0-draft
**Status:** Draft — normative once tagged 1.0.0

This document specifies a language-agnostic authorization model combining:

- **RBAC** — roles bundling permissions;
- **Hierarchical scoping (ABAC)** — every role grant is bound to a node of a configurable hierarchy and covers that node's whole subtree;
- **Assignment lifecycle** — temporal validity, suspension, auditable revocation;
- **Step-up re-authentication** — short-lived proof of identity required for sensitive actions.

Implementations (reference: Django/Python; planned: Spring Boot/Java) MUST pass the shared conformance suite (see [§12](#12-conformance-test-suite)). The key words MUST, MUST NOT, SHOULD, MAY are to be interpreted as in RFC 2119.

---

## 1. Design goals

1. **Hierarchy is configuration, not schema.** Host applications declare an ordered list of levels; the engine never hardcodes level names or depth. Depth 0 (no hierarchy) MUST degrade to plain RBAC.
2. **The engine owns no domain models.** Scopes and role owners reference host entities through opaque references (e.g. generic foreign keys); resources attach through declared *anchors*.
3. **Views check permissions, never roles.** A role is only a named bundle of permissions. Implementations MAY provide a role-membership check as an escape hatch but MUST document it as discouraged.
4. **Deny by default.** Any question the model cannot answer positively is answered negatively.

Non-goals (v1): multiple/orthogonal hierarchies, DAG scopes, physical tenant isolation (schema-per-tenant), token/session management (delegated to the host's authentication layer).

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Hierarchy** | Ordered list of **levels**, index 0 being the top. `rank(level)` = its index. |
| **Root level** | A level with no associated entity type (e.g. `NATIONAL`). If present it MUST be at rank 0. |
| **Node** | A host entity playing a level's part (e.g. one specific Facility). Every non-root node has exactly one parent node at a strictly higher level (lower rank). Nodes form a forest/tree. |
| **Principal** | The authenticated subject (user). Has `active` and `superuser` flags. |
| **Permission** | An opaque string `<namespace>.<codename>` (e.g. `patients.view_patient`). The catalog is host-defined. |
| **Role** | Named set of permissions, optionally **owned** by a node. |
| **Assignment** | Grant of one role to one principal at one scope: `(principal, role, level, node?)`. Root-level assignments have no node. |
| **Resource** | Any host object access is asked about. A resource is **registered** with an **anchor** (a path from the resource to its node) or **unregistered** (= *global resource*). |
| **Ancestor set** | For a node `n`: `{n} ∪ ancestors(n)`, mapped by level. |

---

## 3. Configuration

An implementation MUST accept a declarative configuration equivalent to:

```
hierarchy:            ordered list of {level, entity_type?, parent_accessor?}
role_owner_levels:    subset of levels allowed to own roles       (default: [])
grantable_permissions: "self" | "any" | explicit list | callable  (default: "self")
reauth:               {enabled, ttl_seconds (default 300), verifiers}
```

Validation rules (MUST be enforced at startup, e.g. framework checks):

- Levels are unique; at most one root level, at rank 0.
- Every non-root level declares its entity type and, except for the first non-root level, how to reach its parent.
- `role_owner_levels ⊆ hierarchy` levels, root excluded.

---

## 4. Scope resolution

### 4.1 Scope chain of a resource

`chain(resource)` is a mapping `level → node` obtained by:

1. Resolving the resource's declared **anchor** to a node (possibly through a multi-hop accessor path, e.g. `encounter → facility`).
2. Walking parent accessors up to the top of the hierarchy.

If the resource is unregistered, `chain` is undefined and the resource is **global**.
If the anchor resolves to nothing (null reference), the resource MUST be treated as **not covered** by any non-root assignment (deny by default), except for superusers.

### 4.2 Coverage rule (normative core)

An assignment `a` **covers** a resource `r` iff:

```
covers(a, r) :=
    a.level is the root level
    OR a.node ∈ ancestor_set(anchor_node(r))        # inclusive subtree rule
```

Consequences implementations MUST honour:

- Coverage is **inclusive downward**: a REGIONAL assignment covers every district, facility, department… under that region.
- Coverage is **never upward**: an assignment at a level deeper than the resource's anchor does not cover it (e.g. FACILITY-scoped assignment vs a resource anchored at REGIONAL).
- Node identity comparison is by identifier, not object identity.

### 4.3 Collection filtering

For listing endpoints, implementations MUST provide a filter primitive equivalent to:

```
accessible_nodes(principal, level L) :=
    superuser → all nodes at L
    otherwise → ⋃ over effective assignments a:
        a.level = root  → all nodes at L
        rank(a.level) ≤ rank(L) → descendants-or-self of a.node at L
        rank(a.level) > rank(L) → ∅ contribution
```

and a resource-set filter: `r` visible iff global, or `anchor_node(r)`'s ancestor set intersects the principal's assignment nodes (equivalently: anchor node ∈ accessible nodes). Filtering MUST be expressible as a database-level query (no per-row application checks).

---

## 5. Permission decision

```
has_perm(principal, permission, resource?) :=
    principal.active = false                → false
    principal.superuser = true              → true
    ∃ effective assignment a such that:
         permission ∈ a.role.permissions
         AND ( resource is absent
               OR resource is global
               OR covers(a, resource) )     → true
    otherwise                               → false
```

Where **effective** is defined in [§8.2](#82-effectiveness). Notes:

- Global resources skip the *scope* check only; the RBAC check still applies.
- The permission catalog is flat; there is no implication between permissions (`change` does not imply `view`).
- HTTP mapping (RECOMMENDED for REST implementations): `GET/HEAD → view_*`, `POST → add_*`, `PUT/PATCH → change_*`, `DELETE → delete_*`; read access MUST require `view_*` (no anonymous-read default).
- **Write guard:** create/update operations MUST validate that the *resulting* object's anchor is covered by the actor (object-level checks on input data, since the object may not exist yet).

---

## 6. Roles and ownership (multi-tenancy)

A role has an optional **owner** node whose level MUST be in `role_owner_levels`.

| owner | meaning |
|---|---|
| absent | **System role** — universal, visible everywhere, managed centrally. |
| node X | **Custom role** — belongs to X's subtree ("tenant" role). |

Normative rules:

- **R1 — Visibility:** a role is visible to a principal iff it has no owner, or the principal has an effective assignment covering the owner node.
- **R2 — Assignability:** an assignment using a custom role MUST have its scope node inside the owner's subtree (descendant-or-self). Root-level assignments of custom roles are forbidden.
- **R3 — Name uniqueness:** `(name, owner)` MUST be unique. System role names MUST be globally unique.
- **R4 — Delegated management:** creating/editing/deleting a custom role owned by X requires the `roles.manage_roles` permission effective on a scope covering X. System roles require `roles.manage_global_roles` (or superuser).
- **R5 — Anti-escalation:** when `grantable_permissions = "self"` (default), an actor MUST NOT add to any role a permission the actor does not themself hold effectively at the role's owner scope (at global scope for system roles). Superusers are exempt. `"any"` disables the rule; an explicit list restricts grantable permissions to that list.
- **R6 — Change amplification:** modifying a role's permission set changes the rights of every assignee; it MUST emit `role.permissions_changed` ([§9](#9-events)).

---

## 7. Step-up re-authentication (ReAuth)

Optional module. When enabled:

1. **Issuance:** the principal presents a fresh proof to a **verifier** (v1: password; future: PIN, TOTP, WebAuthn). On success the implementation issues an opaque random token bound to the principal, stored server-side with TTL `reauth.ttl_seconds` (default 300).
2. **Consumption:** a protected action MUST receive the token (HTTP: header `X-ReAuth-Token`). Verification MUST be atomic check-and-delete (**single use**), MUST match the requesting principal, and MUST fail on expiry.
3. **Failure contract (HTTP):** status 403 with a machine-readable body containing at least `{"reauth_required": true}` so clients can trigger the flow.
4. **Invalidation:** all outstanding tokens of a principal MUST be invalidated on credential change and SHOULD be invalidatable in bulk (per-principal index).
5. **Superusers are NOT exempt** from re-authentication.
6. ReAuth is evaluated *in addition to* — never instead of — the permission decision of §5.

---

## 8. Assignment lifecycle

### 8.1 States

```
ACTIVE ⇄ SUSPENDED
ACTIVE | SUSPENDED → REVOKED   (terminal)
```

- Assignments MUST NOT be hard-deleted; revocation records `revoked_by`, `revoked_at`, `reason`.
- Grants record `granted_by`, `granted_at`.

### 8.2 Effectiveness

```
effective(a, now) :=
    a.status = ACTIVE
    AND a.valid_from ≤ now
    AND (a.valid_until is null OR now < a.valid_until)
```

Expiry MUST be evaluated at read time. Implementations MUST NOT rely on scheduled jobs to flip state for correctness (a job MAY exist for housekeeping/notifications).

### 8.3 Duplicate prevention

`(principal, role, level, node)` MUST be unique among non-REVOKED assignments.

---

## 9. Events

Implementations MUST emit the following events (mechanism is idiomatic: Django signals, Spring application events) so hosts can plug auditing:

| Event | Payload (minimum) |
|---|---|
| `assignment.granted` | assignment, actor |
| `assignment.suspended` / `assignment.reactivated` | assignment, actor, reason? |
| `assignment.revoked` | assignment, actor, reason? |
| `role.permissions_changed` | role, added[], removed[], actor |
| `reauth.issued` / `reauth.consumed` / `reauth.failed` | principal, (no token value) |

The package itself does not persist audit logs.

---

## 10. Introspection endpoint — `GET /me/access/`

REST implementations MUST expose the principal's effective access:

```json
{
  "principal": {"id": "…", "superuser": false, "active": true},
  "permissions": ["patients.view_patient", "…"],
  "assignments": [
    {
      "role": {"id": "…", "name": "Doctor", "system": true},
      "level": "DEPARTMENT",
      "scope": {"id": "…", "label": "Maternity — Ndoungue Hospital"},
      "status": "ACTIVE",
      "valid_until": null,
      "permissions": ["patients.view_patient", "…"]
    }
  ]
}
```

- `permissions` (top level) = union over effective assignments (convenience for UIs).
- Only **effective** assignments appear by default.
- Any claims embedded in authentication tokens (JWT…) are **informative only**; this endpoint and server-side checks are the sole authorities.

---

## 11. Caching & revocation guarantees

- A revocation/suspension MUST take effect on the next request at the latest. Therefore assignment/permission data MUST NOT be cached across requests unless the cache is invalidated by the events of §9.
- Per-request memoization is RECOMMENDED (the §5 decision may run many times per request).
- Configuration (hierarchy, registry) is immutable at runtime and MAY be cached indefinitely.

---

## 12. Conformance test suite

Shared, implementation-agnostic test cases live in `conformance/cases/*.json`. Each implementation ships an **adapter** that loads a case, materializes it (models, storage), runs the checks, and compares outcomes.

### 12.1 Case format

```json
{
  "description": "human-readable purpose",
  "config": {
    "hierarchy": ["NATIONAL", "REGIONAL", "FACILITY"],
    "root_level": "NATIONAL",
    "role_owner_levels": ["FACILITY"],
    "grantable_permissions": "self"
  },
  "nodes": [
    {"id": "north", "level": "REGIONAL"},
    {"id": "hosp-1", "level": "FACILITY", "parent": "north"}
  ],
  "roles": [
    {"id": "doctor", "permissions": ["patients.view_patient"], "owner": null}
  ],
  "principals": [
    {
      "id": "alice", "active": true, "superuser": false,
      "assignments": [
        {"role": "doctor", "level": "FACILITY", "node": "hosp-1",
         "status": "ACTIVE", "valid_from": null, "valid_until": null}
      ]
    }
  ],
  "resources": [
    {"id": "patient-1", "anchor": "hosp-1"},
    {"id": "icd-catalog", "anchor": null}
  ],
  "now": "2026-07-04T12:00:00Z",
  "checks": [
    {"type": "perm", "principal": "alice", "permission": "patients.view_patient",
     "resource": "patient-1", "expect": true},
    {"type": "accessible_nodes", "principal": "alice", "level": "FACILITY",
     "expect": ["hosp-1"]},
    {"type": "role_visible", "principal": "alice", "role": "doctor", "expect": true},
    {"type": "can_grant_permission", "actor": "alice", "role": "doctor",
     "permission": "users.manage_roles", "expect": false}
  ]
}
```

Check types (v1): `perm` (with optional `resource`), `accessible_nodes`, `resource_visible`, `role_visible`, `role_assignable` (role at level/node), `can_grant_permission`, `write_guard` (scope-only write admission of §5: superuser, global resource, or an effective assignment covering the resource's anchor), `access_summary` (the engine-level content of §10: effective `permissions` union and effective `assignments` as `{role, level, scope}`). `now` fixes the clock for temporal cases.

Resource fixtures: `"anchor": <node-id>` = registered resource; `"anchor": null` = **global** resource (materialized on an unregistered model) — unless `"registered": true`, which materializes a registered resource whose anchor resolves to nothing (§4.1 deny case).

### 12.1.1 Stateful ReAuth scripts

Cases exercising §7 carry a top-level `"reauth": {"ttl": <seconds>, "script": [...]}` executed in order against a clock starting at `now`. Principals MAY declare a `"password"`. Steps:

```json
{"op": "issue",   "principal": "alice", "password": "…", "expect": true, "save_as": "t1"}
{"op": "consume", "principal": "alice", "token": "$t1", "expect": true}
{"op": "advance", "seconds": 301}
{"op": "invalidate_all", "principal": "alice"}
```

`issue.expect` states whether a token is obtained; `$name` references a saved token; `consume` of an unknown/expired/foreign/already-used token MUST be false, and a failed consume by the wrong principal MUST NOT burn the token.

### 12.2 Conformance claim

An implementation may claim conformance to spec version X iff it passes **all** cases shipped with that version. Cases are append-only within a minor version; behavioural changes require a major bump.

---

## 13. Versioning

This spec follows SemVer. The reference implementation (`django-scoped-access`) tracks the spec's major version. Breaking behavioural changes to §4–§8 require a major version bump and a migration note.
