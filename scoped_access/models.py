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
from .exceptions import (
    AssignmentDeletionError,
    AssignmentManagementPermissionError,
    AssignmentScopeError,
    InvalidAssignmentTransitionError,
    RoleAssignmentError,
    RoleManagementPermissionError,
    RoleOwnershipError,
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
    owner_ct = models.ForeignKey(ContentType, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
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

    def _validate_owner(self) -> None:
        """Enforce that custom-role owners belong to an allowed hierarchy level."""
        if self.owner_id is None:
            if self.owner_ct_id is not None or self.owner_level is not None:
                raise RoleOwnershipError("A system role cannot define owner metadata without an owner.")
            return
        if self.owner_ct_id is None:
            raise RoleOwnershipError("A custom role requires both owner_ct and owner_id.")

        owner = self.owner
        if owner is None:
            raise RoleOwnershipError("The custom role owner does not exist.")

        from .conf import get_config

        cfg = get_config()
        matching_levels = [
            level
            for level in cfg.hierarchy.levels_for_model(type(owner))
            if level.queryset().filter(pk=owner.pk).exists()
        ]
        if self.owner_level is None:
            if len(matching_levels) != 1:
                raise RoleOwnershipError("owner_level is required when the owner model maps to multiple levels.")
            self.owner_level = matching_levels[0].name
        elif self.owner_level not in {level.name for level in matching_levels}:
            raise RoleOwnershipError("owner_level does not match the configured hierarchy node.")

        if self.owner_level not in cfg.role_owner_levels:
            raise RoleOwnershipError(f"Level '{self.owner_level}' is not allowed to own roles.")

    def save(self, *args, **kwargs):
        self._validate_owner()
        return super().save(*args, **kwargs)

    # ── Permission set changes (SPEC R6) — always through these ──────────
    # Changing a role's permissions silently changes the rights of every
    # assignee: it MUST emit role_permissions_changed (§9), which plain
    # `role.permissions.add(...)` cannot attribute to an actor.

    def _labels(self, perms) -> list[str]:
        return sorted(f"{p.content_type.app_label}.{p.codename}" for p in perms)

    def grant_permissions(self, *perms, by) -> None:
        from . import engine
        from .role_permissions import managed_role_permission_mutation

        if not engine.can_manage_role(by, self):
            raise RoleManagementPermissionError("The actor cannot manage this role.")
        added = [p for p in perms if not self.permissions.filter(pk=p.pk).exists()]
        forbidden = [label for label in self._labels(added) if not engine.can_grant_permission(by, self, label)]
        if forbidden:
            raise RoleManagementPermissionError(
                f"The actor cannot delegate these permissions: {', '.join(forbidden)}."
            )
        with managed_role_permission_mutation():
            self.permissions.add(*perms)
        if added:
            signals.role_permissions_changed.send(
                sender=type(self), role=self, added=self._labels(added), removed=[], actor=by
            )
            cache.invalidate_all()

    def revoke_permissions(self, *perms, by) -> None:
        from . import engine
        from .role_permissions import managed_role_permission_mutation

        if not engine.can_manage_role(by, self):
            raise RoleManagementPermissionError("The actor cannot manage this role.")
        removed = [p for p in perms if self.permissions.filter(pk=p.pk).exists()]
        with managed_role_permission_mutation():
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
    role = models.ForeignKey(role_model_label(), on_delete=models.CASCADE, related_name="role_permissions")
    permission = models.ForeignKey("auth.Permission", on_delete=models.CASCADE, related_name="scoped_role_permissions")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["role", "permission"], name="scoped_access_unique_role_perm")]


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

    def grant(self, *, user, role, by, level=None, scope=None, **kwargs):
        """Create an assignment and emit assignment_granted (§9)."""
        if scope is not None:
            kwargs["scope_ct"] = ContentType.objects.get_for_model(type(scope))
            kwargs["scope_id"] = str(scope.pk)
            from .conf import get_config

            cfg = get_config()
            matching_levels = [
                candidate
                for candidate in cfg.hierarchy.levels_for_model(type(scope))
                if candidate.queryset().filter(pk=scope.pk).exists()
            ]
            if level is None:
                if len(matching_levels) != 1:
                    raise AssignmentScopeError(
                        "The scope must match exactly one hierarchy level, or level must be provided explicitly."
                    )
                level = matching_levels[0].name
            elif level not in {candidate.name for candidate in matching_levels}:
                raise AssignmentScopeError("The assignment level does not match the scope node.")
        from . import engine

        if not engine.role_assignable(role, level, scope):
            raise RoleAssignmentError("A custom role can only be assigned inside its owner's subtree.")
        if not engine.can_manage_assignment(by, scope):
            raise AssignmentManagementPermissionError("The actor cannot manage assignments at the target scope.")
        assignment = self.create(user=user, role=role, level=level, granted_by=by, **kwargs)
        signals.assignment_granted.send(sender=self.model, assignment=assignment, actor=by)
        cache.invalidate_user(user.pk)
        return assignment

    def update(self, **kwargs):
        """Prevent bulk updates from bypassing the lifecycle state machine."""
        if "status" in kwargs:
            raise InvalidAssignmentTransitionError(
                "Assignment status must be changed through suspend(), reactivate(), or revoke()."
            )
        return super().update(**kwargs)

    def delete(self):
        """Assignment rows are an audit trail and cannot be hard-deleted."""
        raise AssignmentDeletionError("Scope assignments must be revoked, not deleted.")


class AbstractScopeAssignment(models.Model):
    """Grant of one role to one principal at one scope (SPEC §2).

    level/scope = None → root or flat-RBAC scope: covers everything.
    Never hard-deleted: revocation keeps the row as its own audit trail.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="scoped_assignments")
    role = models.ForeignKey(role_model_label(), on_delete=models.PROTECT, related_name="assignments")

    level = models.CharField(max_length=50, null=True, blank=True)
    scope_ct = models.ForeignKey(ContentType, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    scope_id = models.CharField(max_length=64, null=True, blank=True)
    scope = GenericForeignKey("scope_ct", "scope_id")

    status = models.CharField(max_length=10, choices=AssignmentStatus.choices, default=AssignmentStatus.ACTIVE)
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

    def save(self, *args, **kwargs):
        """Reject direct status changes that bypass lifecycle methods."""
        update_fields = kwargs.get("update_fields")
        writes_status = update_fields is None or "status" in update_fields
        if self.pk is not None and writes_status:
            persisted_status = (
                type(self)._base_manager.filter(pk=self.pk).values_list("status", flat=True).first()
            )
            if persisted_status is not None and persisted_status != self.status:
                raise InvalidAssignmentTransitionError(
                    "Assignment status must be changed through suspend(), reactivate(), or revoke()."
                )
        return super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        """Assignment rows are an audit trail and cannot be hard-deleted."""
        raise AssignmentDeletionError("Scope assignments must be revoked, not deleted.")

    def _transition(self, *, target, allowed_from, **changes) -> None:
        """Apply a state transition atomically against the persisted status."""
        if self.pk is None:
            raise InvalidAssignmentTransitionError("An unsaved assignment cannot change status.")

        changes["status"] = target
        candidates = type(self)._base_manager.filter(pk=self.pk, status__in=allowed_from)
        updated = models.QuerySet.update(candidates, **changes)
        if updated != 1:
            persisted_status = (
                type(self)._base_manager.filter(pk=self.pk).values_list("status", flat=True).first()
            )
            if persisted_status is None:
                raise type(self).DoesNotExist(f"Assignment {self.pk} no longer exists.")
            self.status = persisted_status
            raise InvalidAssignmentTransitionError(
                f"Cannot transition assignment from {persisted_status} to {target}."
            )

        for field, value in changes.items():
            setattr(self, field, value)

    def suspend(self, *, by=None, reason: str = "") -> None:
        self._transition(target=AssignmentStatus.SUSPENDED, allowed_from=(AssignmentStatus.ACTIVE,))
        signals.assignment_suspended.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)

    def reactivate(self, *, by=None, reason: str = "") -> None:
        self._transition(target=AssignmentStatus.ACTIVE, allowed_from=(AssignmentStatus.SUSPENDED,))
        signals.assignment_reactivated.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)

    def revoke(self, *, by=None, reason: str = "") -> None:
        self._transition(
            target=AssignmentStatus.REVOKED,
            allowed_from=(AssignmentStatus.ACTIVE, AssignmentStatus.SUSPENDED),
            revoked_by=by,
            revoked_at=timezone.now(),
            reason=reason,
        )
        signals.assignment_revoked.send(sender=type(self), assignment=self, actor=by, reason=reason)
        cache.invalidate_user(self.user_id)


class ScopeAssignment(AbstractScopeAssignment):
    class Meta:
        swappable = ASSIGNMENT_MODEL_SETTING
        constraints = [
            # SPEC §8.3 — no duplicate among non-revoked assignments.
            #
            # The full tuple constraint cannot protect root assignments on
            # databases where NULL values are distinct. Dedicated partial
            # constraints cover both valid node-less shapes: an explicit
            # root level and flat RBAC (level=None).
            models.UniqueConstraint(
                fields=["user", "role", "level", "scope_ct", "scope_id"],
                condition=~models.Q(status=AssignmentStatus.REVOKED),
                name="scoped_access_unique_live_assignment",
            ),
            models.UniqueConstraint(
                fields=["user", "role", "level"],
                condition=(
                    ~models.Q(status=AssignmentStatus.REVOKED)
                    & models.Q(level__isnull=False, scope_id__isnull=True)
                ),
                name="scoped_access_unique_live_root",
            ),
            models.UniqueConstraint(
                fields=["user", "role"],
                condition=(
                    ~models.Q(status=AssignmentStatus.REVOKED)
                    & models.Q(level__isnull=True, scope_id__isnull=True)
                ),
                name="scoped_access_unique_live_flat",
            ),
        ]
        indexes = [
            models.Index(fields=["user", "status"], name="scoped_assign_user_status_idx"),
            models.Index(fields=["scope_ct", "scope_id"], name="scoped_assign_scope_idx"),
        ]
        permissions = [
            ("manage_assignments", "Can manage scope assignments"),
        ]
