# Quickstart Guide

This guide walks you through setting up **Django Scoped Access** in a new or existing Django project in less than 5 minutes.

---

## 1. Installation

Install the package with `pip` or `uv`:

=== "pip"

    ```bash
    pip install django-scoped-access
    ```

=== "uv"

    ```bash
    uv add django-scoped-access
    ```

If you are using Django REST Framework:

=== "pip"

    ```bash
    pip install "django-scoped-access[drf]"
    ```

=== "uv"

    ```bash
    uv add "django-scoped-access[drf]"
    ```

---

## 2. Update `settings.py`

Add `scoped_access` to your `INSTALLED_APPS` and configure the authentication backend:

```python
# settings.py

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Add scoped_access
    "scoped_access",
    # Optional: DRF
    "rest_framework",
    # Your apps
    "accounts",
    "helpdesk",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",         # Credentials verification
    "scoped_access.backends.ScopedPermissionBackend",    # Scoped authorization
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # Optional per-request cache memoization for high performance
    "scoped_access.cache.ScopedAccessCacheMiddleware",
]
```

---

## 3. Configure the Hierarchy

Define your organizational tree in `settings.py`. Here is a 2-level multi-tenant configuration (Organization → Team):

```python
# settings.py

SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "GLOBAL"},  # Optional root level (covers everything)
        {"level": "ORGANIZATION", "model": "helpdesk.Organization"},
        {"level": "TEAM", "model": "helpdesk.Team", "parent": "organization"},
    ],
    # Organizations are allowed to define their own custom roles
    "ROLE_OWNER_LEVELS": ["ORGANIZATION"],
    "GRANTABLE_PERMISSIONS": "self",
    "REAUTH": {
        "ENABLED": True,
        "TTL": 300,  # 5 minutes
    },
}
```

---

## 4. Run Migrations

Apply the database migrations to create the `Role`, `RolePermission`, and `ScopeAssignment` tables:

```bash
python manage.py migrate
```

---

## 5. Register Resources

Attach domain models to the hierarchy by declaring their **anchor** (the path from the model to a hierarchy node):

```python
# helpdesk/apps.py
from django.apps import AppConfig

class HelpdeskConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "helpdesk"

    def ready(self):
        from scoped_access import register
        from helpdesk.models import Ticket

        # A ticket is anchored to a Team (a hierarchy node)
        register(Ticket, anchor="team")
```

---

## 6. Create Roles & Assignments via API

Use the secure service APIs to create roles and grant assignments:

```python
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from helpdesk.models import Organization, Team
from scoped_access import RoleService, ScopeAssignment

User = get_user_model()
admin = User.objects.get(username="admin")
alice = User.objects.get(username="alice")

acme_org = Organization.objects.create(name="Acme Corp")
support_team = Team.objects.create(organization=acme_org, name="Customer Support")

# 1. Create a System Role (universal)
view_ticket_perm = Permission.objects.get(codename="view_ticket")
change_ticket_perm = Permission.objects.get(codename="change_ticket")

agent_role = RoleService.create(
    name="Support Agent",
    description="Handles support tickets",
    permissions=[view_ticket_perm, change_ticket_perm],
    by=admin,
)

# 2. Grant the role to Alice at the Team scope
ScopeAssignment.objects.grant(
    user=alice,
    role=agent_role,
    scope=support_team,
    by=admin,
)
```

Now, Alice can view and edit any ticket belonging to `support_team`!

---

## 7. Expose REST Endpoints (DRF)

If using Django REST Framework, protect your ViewSets with the scoped mixins and permissions:

```python
# helpdesk/views.py
from rest_framework import viewsets
from helpdesk.models import Ticket
from helpdesk.serializers import TicketSerializer
from scoped_access.drf import (
    RequireReAuth,
    ScopedModelPermission,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
    ScopeWriteGuardMixin,
)

class TicketViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, viewsets.ModelViewSet):
    queryset = Ticket.objects.select_related("team__organization")
    serializer_class = TicketSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action == "destroy":
            # Deleting a ticket requires step-up re-authentication
            permissions.append(RequireReAuth())
        return permissions
```

Register the introspection and re-authentication endpoints in your `urls.py`:

```python
# config/urls.py
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from helpdesk.views import TicketViewSet
from scoped_access.drf import MeAccessView, ReAuthView

router = DefaultRouter()
router.register("tickets", TicketViewSet, basename="ticket")

urlpatterns = [
    path("api/", include(router.urls)),
    # Current user effective access summary
    path("api/me/access/", MeAccessView.as_view(), name="me-access"),
    # Step-up re-authentication token endpoint
    path("api/auth/reauth/", ReAuthView.as_view(), name="reauth"),
]
```

---

## What's Next?

- Read [Core Concepts](concepts.md) for details on scope inheritance and anti-escalation.
- Check [DRF Integration](drf.md) for complete REST best practices.
- Explore [Step-Up Re-Authentication](reauth.md) to secure high-risk actions.
