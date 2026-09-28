# Swappable Models

Similar to Django's `AUTH_USER_MODEL`, Django Scoped Access allows you to replace the default `Role` and `ScopeAssignment` models with custom subclasses of `AbstractRole` and `AbstractScopeAssignment`.

This enables adding custom metadata fields (e.g. `department_code`, `billing_reference`, `external_id`, `custom_tags`) to roles and assignments without forking the package.

---

## 1. Defining Custom Models

Subclass `AbstractRole` or `AbstractScopeAssignment` in one of your Django apps:

```python
# custom_auth/models.py
from django.db import models
from scoped_access.models import (
    AbstractRole,
    AbstractScopeAssignment,
    AssignmentStatus,
)

class CustomRole(AbstractRole):
    # Custom business fields
    external_sync_id = models.CharField(max_length=100, blank=True)
    is_system_critical = models.BooleanField(default=False)

    class Meta(AbstractRole.Meta):
        swappable = "SCOPED_ACCESS_ROLE_MODEL"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "owner_ct", "owner_id"],
                condition=models.Q(owner_id__isnull=False),
                name="custom_unique_custom_role_name",
            ),
            models.UniqueConstraint(
                fields=["name"],
                condition=models.Q(owner_id__isnull=True),
                name="custom_unique_system_role_name",
            ),
        ]
        # Required: the engine checks <app_label>.manage_roles / manage_global_roles.
        permissions = [
            ("manage_roles", "Can manage roles in scope"),
            ("manage_global_roles", "Can manage system roles"),
        ]


class CustomAssignment(AbstractScopeAssignment):
    # Custom audit or metadata fields
    delegation_ticket_id = models.CharField(max_length=50, blank=True)
    notes = models.TextField(blank=True)

    class Meta(AbstractScopeAssignment.Meta):
        swappable = "SCOPED_ACCESS_ASSIGNMENT_MODEL"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role", "level", "scope_ct", "scope_id"],
                condition=~models.Q(status=AssignmentStatus.REVOKED),
                name="custom_unique_live_assignment",
            ),
            models.UniqueConstraint(
                fields=["user", "role", "level"],
                condition=(
                    ~models.Q(status=AssignmentStatus.REVOKED)
                    & models.Q(level__isnull=False, scope_id__isnull=True)
                ),
                name="custom_unique_live_root",
            ),
            models.UniqueConstraint(
                fields=["user", "role"],
                condition=(
                    ~models.Q(status=AssignmentStatus.REVOKED)
                    & models.Q(level__isnull=True, scope_id__isnull=True)
                ),
                name="custom_unique_live_flat",
            ),
        ]
        indexes = [
            models.Index(fields=["user", "status"], name="custom_assign_user_status_idx"),
            models.Index(fields=["scope_ct", "scope_id"], name="custom_assign_scope_idx"),
        ]
        # Required: the engine checks <app_label>.manage_assignments.
        permissions = [
            ("manage_assignments", "Can manage scope assignments"),
        ]
```

---

## 2. Configuring Settings

Set the model pointers in `settings.py` **before running your initial migrations**:

```python
# settings.py
SCOPED_ACCESS_ROLE_MODEL = "custom_auth.CustomRole"
SCOPED_ACCESS_ASSIGNMENT_MODEL = "custom_auth.CustomAssignment"
```

---

## 3. Running Migrations

Generate and run migrations in your app:

```bash
python manage.py makemigrations custom_auth
python manage.py migrate
```

!!! warning "Copy `constraints`, `indexes` and `permissions`"
    `AbstractRole` and `AbstractScopeAssignment` do not declare `constraints`, `indexes` or `permissions`: only the concrete default models do, so your subclasses must declare them too. Without the uniqueness constraints, duplicate live assignments become possible. Without the `permissions`, only superusers can manage roles and assignments. The permissions take your app's label: `custom_auth.manage_roles`, `custom_auth.manage_assignments`, and so on.

The rest of the engine (`RoleService`, `ScopeAssignment.objects.grant()`, `has_perm()`, `drf`, etc.) automatically detects and uses your swapped models.
