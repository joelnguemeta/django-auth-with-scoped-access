"""Role, RolePermission, ScopeAssignment (SPEC §6, §8).

Scopes and role owners reference host entities through GenericForeignKeys —
the package's migrations never depend on host models (design goal 2).

Both concrete models are swappable, à la AUTH_USER_MODEL::

    SCOPED_ACCESS_ROLE_MODEL = "myapp.Role"            # subclass AbstractRole
    SCOPED_ACCESS_ASSIGNMENT_MODEL = "myapp.Assignment"  # subclass AbstractScopeAssignment

Set these before the first migrate. Note: with a swapped Role, the
`manage_roles`/`manage_global_roles` permissions carry the custom app's label.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone

from . import cache, signals
from .conf import (
    ASSIGNMENT_MODEL_SETTING,
    ROLE_MODEL_SETTING,
    ensure_swappable_defaults,
    role_model_label,
)

ensure_swappable_defaults()


class AbstractRole(models.Model):
    """Named bundle of permissions, optionally owned by a hierarchy node.

    owner = None  → system role: universal, centrally managed.
    owner = node  → custom role: lives in that node's subtree (SPEC §6).
    """

    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(
        "auth.Permission",
        through="scoped_access.RolePermission",
        related_name="scoped_roles",
        blank=True,
    )

    owner_level = models.CharField(max_length=50, null=True, blank=True)
    owner_ct = models.ForeignKey(
        ContentType, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    owner_id = models.CharField(max_length=64, null=True, blank=True)
    owner = GenericForeignKey("owner_ct", "owner_id")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    @property
    def is_system(self) -> bool:
        return self.owner_id is None

    def __str__(self) -> str:
        return self.name if self.is_system else f"{self.name} @ {self.owner}"

    # ── Permission set changes (SPEC R6) — always through these ──────────
    # Changing a role's permissions silently changes the rights of every
    # assignee: it MUST emit role_permissions_changed (§9), which plain
    # `role.permissions.add(...)` cannot attribute to an actor.

    def _labels(self, perms) -> list[str]:
        return sorted(f"{p.content_type.app_label}.{p.codename}" for p in perms)

    def grant_permissions(self, *perms, by=None) -> None:
        added = [p for p in perms if not self.permissions.filter(pk=p.pk).exists()]
        self.permissions.add(*perms)
        if added:
            signals.role_permissions_changed.send(
                sender=type(self), role=self, added=self._labels(added), removed=[], actor=by
            )
            cache.invalidate_all()

    def revoke_permissions(self, *perms, by=None) -> None:
        removed = [p for p in perms if self.permissions.filter(pk=p.pk).exists()]
        self.permissions.remove(*perms)
        if removed:
            signals.role_permissions_changed.send(
                sender=type(self), role=self, added=[], removed=self._labels(removed), actor=by
            )
            cache.invalidate_all()


class Role(AbstractRole):
    class Meta:
        swappable = ROLE_MODEL_SETTING
        constraints = [
            # R3 — custom role names unique per owner; system role names global.
            models.UniqueConstraint(
                fields=["name", "owner_ct", "owner_id"],
                condition=models.Q(owner_id__isnull=False),
                name="scoped_access_unique_custom_role_name",
            ),
            models.UniqueConstraint(
                fields=["name"],
                condition=models.Q(owner_id__isnull=True),
                name="scoped_access_unique_system_role_name",
            ),
        ]
        permissions = [
            ("manage_roles", "Can manage roles in scope"),
            ("manage_global_roles", "Can manage system roles"),
        ]


class RolePermission(models.Model):
    role = models.ForeignKey(
        role_model_label(), on_delete=models.CASCADE, related_name="role_permissions"
    )
    permission = models.ForeignKey(
        "auth.Permission", on_delete=models.CASCADE, related_name="scoped_role_permissions"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["role", "permission"], name="scoped_access_unique_role_perm")
        ]


class AssignmentStatus(models.TextChoices):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"  # terminal


class ScopeAssignmentQuerySet(models.QuerySet):
    def effective(self, at=None):
        """SPEC §8.2 — evaluated at read time, never by a scheduled job."""
        at = at or timezone.now()
        return self.filter(status=AssignmentStatus.ACTIVE).filter(
            models.Q(valid_from__isnull=True) | models.Q(valid_from__lte=at),
            models.Q(valid_until__isnull=True) | models.Q(valid_until__gt=at),
        )

    def grant(self, *, user, role, level=None, scope=None, by=None, **kwargs):
        """Create an assignment and emit assignment_granted (§9)."""
        if scope is not None:
            kwargs["scope_ct"] = ContentType.objects.get_for_model(type(scope))
            kwargs["scope_id"] = str(scope.pk)
        assignment = self.create(user=user, role=role, level=level, granted_by=by, **kwargs)
        signals.assignment_granted.send(sender=self.model, assignment=assignment, actor=by)
        cache.invalidate_user(user.pk)
        return assignment


class AbstractScopeAssignment(models.Model):
    """Grant of one role to one principal at one scope (SPEC §2).

    level/scope = None → root or flat-RBAC scope: covers everything.
    Never hard-deleted: revocation keeps the row as its own audit trail.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scoped_assignments"
    )
    role = models.ForeignKey(
        role_model_label(), on_delete=models.PROTECT, related_name="assignments"
    )

    level = models.CharField(max_length=50, null=True, blank=True)
    scope_ct = models.ForeignKey(
        ContentType, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    scope_id = models.CharField(max_length=64, null=True, blank=True)
    scope = GenericForeignKey("scope_ct", "scope_id")

    status = models.CharField(
        max_length=10, choices=AssignmentStatus.choices, default=AssignmentStatus.ACTIVE
    )
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)

    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)

    objects = ScopeAssignmentQuerySet.as_manager()

    class Meta:
        abstract = True

    @property
    def is_root_scope(self) -> bool:
        return self.scope_id is None

    def __str__(self) -> str:
        target = self.scope if self.scope_id else "GLOBAL"
        return f"{self.user} → {self.role.name} @ {target} [{self.status}]"

    # ── Lifecycle (SPEC §8.1) — always through these, never hard-delete ──

    def suspend(self, *, by=None, reason: str = "") -> None:
        self.status = AssignmentStatus.SUSPENDED
        self.save(update_fields=["status"])
        signals.assignment_suspended.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)

    def reactivate(self, *, by=None, reason: str = "") -> None:
        self.status = AssignmentStatus.ACTIVE
        self.save(update_fields=["status"])
        signals.assignment_reactivated.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)

    def revoke(self, *, by=None, reason: str = "") -> None:
        self.status = AssignmentStatus.REVOKED
        self.revoked_by = by
        self.revoked_at = timezone.now()
        self.reason = reason
        self.save(update_fields=["status", "revoked_by", "revoked_at", "reason"])
        signals.assignment_revoked.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)


class ScopeAssignment(AbstractScopeAssignment):
    class Meta:
        swappable = ASSIGNMENT_MODEL_SETTING
        constraints = [
            # SPEC §8.3 — no duplicate among non-revoked assignments.
            models.UniqueConstraint(
                fields=["user", "role", "level", "scope_ct", "scope_id"],
                condition=~models.Q(status=AssignmentStatus.REVOKED),
                name="scoped_access_unique_live_assignment",
            )
        ]
        indexes = [
            models.Index(fields=["user", "status"], name="scoped_assign_user_status_idx"),
            models.Index(fields=["scope_ct", "scope_id"], name="scoped_assign_scope_idx"),
        ]
        permissions = [
            ("manage_assignments", "Can manage scope assignments"),
        ]
