# django-scoped-access

> **Pre-alpha.** Reference implementation of the [Scoped Access specification](SPEC.md) — not yet released.

Authorization for Django combining **RBAC** (roles bundling permissions), **hierarchical scoping** (every role grant is bound to a node of a *configurable* hierarchy and covers its whole subtree), **assignment lifecycle** (validity windows, suspension, auditable revocation) and **step-up re-authentication**.

The hierarchy is configuration, not schema — the same package serves:

```python
# A national health information system (6 levels)
SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "NATIONAL"},
        {"level": "REGIONAL", "model": "geography.Region"},
        {"level": "DISTRICT", "model": "geography.District", "parent": "region"},
        {"level": "FACILITY", "model": "organization.Facility", "parent": "district"},
    ],
    "ROLE_OWNER_LEVELS": ["FACILITY"],   # facilities manage their own custom roles
}

# A simple multi-tenant SaaS (1 level)
SCOPED_ACCESS = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "accounts.Organization"}],
}

# No multi-tenancy at all → plain RBAC
SCOPED_ACCESS = {"HIERARCHY": []}
```

Resources attach to the hierarchy through declared anchors:

```python
import scoped_access.registry as registry

registry.register(Patient, anchor="department")
registry.register(Diagnosis, anchor="encounter__facility")
# unregistered models are global (RBAC applies, scoping doesn't)
```

## Specification & conformance

Behaviour is defined by [SPEC.md](SPEC.md) and enforced by the language-agnostic [conformance suite](conformance/) — shared with other planned implementations (Spring Boot). Run it:

```bash
uv run pytest
```

## Status

- [x] Spec v0.1.0-draft + conformance cases (coverage, lifecycle, tenancy, flat RBAC)
- [x] Core engine, models, permission backend
- [ ] DRF glue (`[drf]` extra) — permissions, queryset mixin, `/me/access/`
- [ ] Step-up re-authentication (`[reauth]` extra)
- [ ] Migration guides (from per-level FK schemas, from role-checking code)

License: TBD.
