# Django Scoped Access

<p align="center">
  <strong>Next-Generation Authorization for Django</strong><br>
  <em>RBAC + Hierarchical Scoping (ABAC) + Temporal Lifecycle + Step-Up Re-Authentication</em>
</p>

---

## What is Django Scoped Access?

**Django Scoped Access** is an authorization engine for Django applications that require fine-grained, hierarchical, multi-tenant, or organization-level access control. It combines the simplicity of **Role-Based Access Control (RBAC)** with the flexibility of **Attribute-Based Access Control (ABAC)** across arbitrary tree hierarchies.

Instead of hardcoding organization levels, foreign keys, or tenant IDs into your authorization logic, **the hierarchy is pure configuration**.

```
                   ┌──────────────────────────────┐
                   │           NATIONAL           │ (Root level)
                   └──────────────┬───────────────┘
                                  │
                   ┌──────────────▼──────────────┐
                   │           REGIONAL          │
                   └──────────────┬───────────────┘
                                  │
                   ┌──────────────▼──────────────┐
                   │           DISTRICT          │
                   └──────────────┬───────────────┘
                                  │
                   ┌──────────────▼──────────────┐
                   │           FACILITY          │ (Can own custom roles)
                   └─────────────────────────────┘
```

---

## Key Features

- 🌲 **Hierarchy as Configuration, Not Schema**: Support everything from flat RBAC (0 levels), simple multi-tenant SaaS (1 level: Organization), to deep organizational systems (Regions, Districts, Facilities, Units) without changing your models.
- 🎯 **Domain Model Agnosticism**: The engine never owns your domain models. Scopes and role owners link to host models via generic references (`GenericForeignKey`).
- 🔒 **Inclusive Downward Scope Coverage**: An assignment granted at a `REGIONAL` scope automatically covers all descendants (Districts, Facilities, Units) in that region's subtree, and never upwards.
- 🏢 **Multi-Tenancy & Custom Tenant Roles**: Tenants can manage their own custom roles within their scope without global admin intervention, protected by built-in **anti-escalation rules (R5)**.
- ⏱️ **Temporal Lifecycle & Audit Trail**: Assignments support `valid_from` and `valid_until` windows, suspension (`SUSPENDED`), and auditable revocation (`REVOKED`). Assignments are **never hard-deleted**.
- 🛡️ **Step-Up Re-Authentication (ReAuth)**: Require short-lived, single-use proof of identity (passwords, PINs, WebAuthn, TOTP) for highly sensitive endpoints (e.g., payouts, deletions, exports). Superusers are not exempt.
- ⚡ **Database-Level Query Filtering**: List views and collection endpoints filter items directly in SQL via `scope_filter_q()`, preventing in-memory filtering bottlenecks.
- 🚀 **First-Class Django REST Framework (DRF) Support**: Ships with drop-in permissions (`ScopedModelPermission`, `ScopeObjectPermission`), queryset mixins (`ScopeQuerySetMixin`), write guards (`ScopeWriteGuardMixin`), and introspection endpoints (`GET /me/access/`).
- 🧩 **Zero-Bypass Architecture**: Internal mutation locks protect role and assignment modifications from bypassing lifecycle audit trails and permission checks.

---

## Architectural Comparison

| Feature | Standard Django RBAC | django-guardian (Object perms) | Django Scoped Access |
|---|:---:|:---:|:---:|
| **Model** | Global permissions | Explicit Row-by-Row permissions | Hierarchical Subtree Scoping (ABAC) |
| **Database Overhead** | Minimal | High (Row per user/perm/object) | Minimal (O(assignments) SQL clauses) |
| **Multi-Tenancy & Trees** | ❌ None | ⚠️ Manual joins & queries | ✅ Native (Inclusive downward) |
| **Delegated Tenant Roles** | ❌ No | ❌ No | ✅ Native with Anti-escalation |
| **Temporal Validity** | ❌ No | ❌ No | ✅ Native (`valid_from`/`valid_until`) |
| **Audit Trail (No Hard Delete)** | ❌ No | ❌ No | ✅ Native (Terminal REVOKED) |
| **Step-Up Re-Authentication** | ❌ No | ❌ No | ✅ Native (Single-use tokens) |
| **DRF Write Guard** | ❌ No | ❌ No | ✅ Native (Validates target scope) |

---

## How It Works in 30 Seconds

### 1. Declare Your Hierarchy

```python
# settings.py
SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "NATIONAL"},
        {"level": "REGIONAL", "model": "geography.Region"},
        {"level": "DISTRICT", "model": "geography.District", "parent": "region"},
        {"level": "FACILITY", "model": "organization.Facility", "parent": "district"},
    ],
    "ROLE_OWNER_LEVELS": ["FACILITY"],
    "GRANTABLE_PERMISSIONS": "self",
}
```

### 2. Register Resource Anchors

```python
# apps.py or models.py
from scoped_access import register

register(Patient, anchor="facility")
register(MedicalRecord, anchor="patient__facility")
```

### 3. Protect DRF Endpoints

```python
# views.py
from rest_framework.viewsets import ModelViewSet
from scoped_access.drf import (
    RequireReAuth,
    ScopedModelPermission,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
    ScopeWriteGuardMixin,
)

class PatientViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, ModelViewSet):
    queryset = Patient.objects.all()
    serializer_class = PatientSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action == "destroy":
            permissions.append(RequireReAuth())
        return permissions
```

---

## Next Steps

- Check out the [Quickstart Guide](quickstart.md) to set up Django Scoped Access in under 5 minutes.
- Learn about [Core Concepts](concepts.md) to understand scope chains, coverage rules, and anti-escalation.
- Dive into the [Configuration Reference](configuration.md) to explore all available settings.
- Read the [Formal Specification (SPEC)](spec.md) for the complete normative model.
