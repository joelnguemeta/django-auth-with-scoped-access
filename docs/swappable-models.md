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

The rest of the engine (`RoleService`, `ScopeAssignment.objects.grant()`, `has_perm()`, `drf`, etc.) automatically detects and uses your swapped models.
