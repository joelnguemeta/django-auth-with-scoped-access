# django-scoped-access

<p align="center">
  <a href="https://pypi.org/project/django-scoped-access/"><img src="https://img.shields.io/pypi/v/django-scoped-access.svg?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/django-scoped-access/"><img src="https://img.shields.io/pypi/pyversions/django-scoped-access.svg" alt="Python Versions"></a>
  <a href="https://pypi.org/project/django-scoped-access/"><img src="https://img.shields.io/pypi/djversions/django-scoped-access.svg" alt="Django Versions"></a>
  <a href="https://django-auth-with-scoped-access.readthedocs.io/"><img src="https://img.shields.io/readthedocs/django-auth-with-scoped-access.svg" alt="Documentation Status"></a>
  <a href="https://github.com/joelnguemeta/django-auth-with-scoped-access/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <strong>Hierarchical Scoped Authorization (ABAC) + RBAC + Temporal Lifecycle + Step-Up Re-Authentication for Django & DRF.</strong><br>
  <em>Reference implementation of the <a href="SPEC.md">Scoped Access Specification</a>.</em>
</p>

---

## 📖 Overview

**django-scoped-access** brings fine-grained, hierarchical multi-tenant access control to Django without polluting your business models or hardcoding organizational trees into database schemas.

Whether building a single-tenant app (flat RBAC), a multi-tenant B2B SaaS (Organization → Team), or a complex organizational system (National → Regional → District → Facility → Department), **the hierarchy is pure configuration**.

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
                   │           FACILITY          │ (Can manage custom roles)
                   └─────────────────────────────┘
```

---

## ✨ Key Features

- 🌲 **Hierarchy as Configuration, Not Schema**: Configure any arbitrary tree depth or degrade to standard RBAC at depth 0.
- 🎯 **Domain Agnostic**: The engine never owns your models. Hierarchy nodes and role owners link via generic relations (`GenericForeignKey`).
- 🔒 **Inclusive Downward Scope Coverage**: A role grant at `REGIONAL` covers all descendant nodes (Districts, Facilities, Units) in that subtree, and never upwards.
- 🛡️ **Anti-Escalation Protection (Rule R5)**: Tenant admins can manage custom roles within their scope, but can **never** grant permissions they do not possess themselves.
- ⏱️ **Temporal Validity & Audit Trail**: Assignments support `valid_from` / `valid_until` windows and status transitions (`ACTIVE` ⇄ `SUSPENDED` → `REVOKED`). Assignments are **never hard-deleted**.
- 🔐 **Step-Up Re-Authentication (ReAuth)**: Require fresh, single-use proof of identity (passwords, PIN, WebAuthn, TOTP) for high-risk actions. Superusers are not exempt.
- ⚡ **Database-Level Query Filtering**: SQL-level filtering (`scope_filter_q()`) for collection views—no in-memory Python iteration.
- 🚀 **Full Django REST Framework (DRF) Integration**: Drop-in permissions (`ScopedModelPermission`, `ScopeObjectPermission`), query mixins (`ScopeQuerySetMixin`), write guards (`ScopeWriteGuardMixin`), and introspection endpoints (`GET /me/access/`).

---

## ⚡ Quickstart (5 Minutes)

### 1. Installation

```bash
# With pip
pip install "django-scoped-access[drf]"

# With uv
uv add "django-scoped-access[drf]"
```

### 2. Configuration (`settings.py`)

```python
INSTALLED_APPS = [
    ...,
    "scoped_access",
    "rest_framework",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "scoped_access.backends.ScopedPermissionBackend",
]

SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "GLOBAL"},
        {"level": "ORGANIZATION", "model": "accounts.Organization"},
        {"level": "TEAM", "model": "accounts.Team", "parent": "organization"},
    ],
    "ROLE_OWNER_LEVELS": ["ORGANIZATION"],
    "GRANTABLE_PERMISSIONS": "self",
    "REAUTH": {"ENABLED": True, "TTL": 300},
}
```

Apply database migrations:

```bash
python manage.py migrate
```

### 3. Register Resource Anchors

Declare the path from your business models to their hierarchy node:

```python
# helpdesk/apps.py
from django.apps import AppConfig

class HelpdeskConfig(AppConfig):
    name = "helpdesk"

    def ready(self):
        from scoped_access import register
        from helpdesk.models import Ticket

        # A Ticket is anchored to a Team
        register(Ticket, anchor="team")
```

For fail-closed deployments, enable `STRICT_REGISTRATION` and declare intentionally global models with `register_global(Model)`.

### 4. Create Roles & Grant Assignments

```python
from scoped_access import RoleService, ScopeAssignment
from helpdesk.models import Team

support_team = Team.objects.get(name="Support")

# 1. Create a System Role
agent_role = RoleService.create(
    name="Support Agent",
    permissions=[view_ticket_perm, change_ticket_perm],
    by=admin_user,
)

# 2. Grant the role to Alice at the Team scope
ScopeAssignment.objects.grant(
    user=alice,
    role=agent_role,
    scope=support_team,
    by=admin_user,
)
```

### 5. Protect DRF Endpoints

```python
# helpdesk/views.py
from scoped_access.drf import (
    RequireReAuth,
    ScopedModelViewSet,
)

class TicketViewSet(ScopedModelViewSet):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action == "destroy":
            # Deleting tickets requires Step-Up Re-Authentication
            permissions.append(RequireReAuth())
        return permissions
```

---

## 🔍 Introspection Endpoint (`GET /me/access/`)

Wire the standard introspection and reauth views in `urls.py`:

```python
from django.urls import path
from scoped_access.drf import MeAccessView, ReAuthView

urlpatterns = [
    path("api/me/access/", MeAccessView.as_view(), name="me-access"),
    path("api/auth/reauth/", ReAuthView.as_view(), name="reauth"),
]
```

Example JSON output from `GET /api/me/access/`:

```json
{
  "principal": {"id": "42", "superuser": false, "active": true},
  "permissions": ["helpdesk.view_ticket", "helpdesk.change_ticket"],
  "assignments": [
    {
      "role": {"id": "7", "name": "Support Agent", "system": true},
      "level": "TEAM",
      "scope": {"id": "12", "label": "Customer Support — Acme Corp"},
      "status": "ACTIVE",
      "valid_until": null,
      "permissions": ["helpdesk.view_ticket", "helpdesk.change_ticket"]
    }
  ]
}
```

---

## 🧪 Testing & Conformance

Django Scoped Access is verified against a language-agnostic test suite defined in [SPEC.md](SPEC.md) and [`conformance/`](conformance/):

```bash
uv run pytest
```

---

## 📚 Documentation

Complete documentation is available at [https://django-auth-with-scoped-access.readthedocs.io/](https://django-auth-with-scoped-access.readthedocs.io/):

- [Quickstart Guide](https://django-auth-with-scoped-access.readthedocs.io/quickstart/)
- [Core Concepts & Architecture](https://django-auth-with-scoped-access.readthedocs.io/concepts/)
- [Configuration Reference](https://django-auth-with-scoped-access.readthedocs.io/configuration/)
- [Django REST Framework (DRF) Integration](https://django-auth-with-scoped-access.readthedocs.io/drf/)
- [Step-Up Re-Authentication (ReAuth)](https://django-auth-with-scoped-access.readthedocs.io/reauth/)
- [Lifecycle & Auditability](https://django-auth-with-scoped-access.readthedocs.io/lifecycle/)
- [Security Guide & Threat Model](https://django-auth-with-scoped-access.readthedocs.io/security/)
- [Formal Specification (SPEC)](https://django-auth-with-scoped-access.readthedocs.io/spec/)

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
