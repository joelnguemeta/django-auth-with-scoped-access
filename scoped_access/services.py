"""Actor-aware role management API enforcing SPEC R4 and R5."""

from __future__ import annotations

from django.db import transaction

from . import cache, engine
from .conf import get_role_model
from .exceptions import RoleManagementPermissionError
from .mutations import managed_role_mutation


class RoleService:
    """Create, edit and delete roles through authorization checks."""

    @staticmethod
    @transaction.atomic
    def create(*, by, permissions=(), **fields):
        role = get_role_model()(**fields)
        role._validate_owner()
        if not engine.can_manage_role(by, role):
            raise RoleManagementPermissionError("The actor cannot create this role.")
        with managed_role_mutation():
            role.save()
        if permissions:
            role.grant_permissions(*permissions, by=by)
        return role

    @staticmethod
    @transaction.atomic
    def update(role, *, by, **changes):
        allowed = {"name", "description", "owner", "owner_level"}
        unknown = set(changes) - allowed
        if unknown:
            raise TypeError(f"Unsupported role fields: {', '.join(sorted(unknown))}.")
        if not engine.can_manage_role(by, role):
            raise RoleManagementPermissionError("The actor cannot edit this role.")

        original = {field: getattr(role, field) for field in allowed}
        try:
            for field, value in changes.items():
                setattr(role, field, value)
            if changes.get("owner", object()) is None and "owner_level" not in changes:
                role.owner_level = None

            role._validate_owner()
            if not engine.can_manage_role(by, role):
                raise RoleManagementPermissionError("The actor cannot move this role to the target owner.")
            with managed_role_mutation():
                role.save()
        except Exception:
            for field, value in original.items():
                setattr(role, field, value)
            raise
        cache.invalidate_all()
        return role

    @staticmethod
    def grant_permissions(role, *permissions, by) -> None:
        role.grant_permissions(*permissions, by=by)

    @staticmethod
    def revoke_permissions(role, *permissions, by) -> None:
        role.revoke_permissions(*permissions, by=by)

    @staticmethod
    @transaction.atomic
    def delete(role, *, by) -> None:
        if not engine.can_manage_role(by, role):
            raise RoleManagementPermissionError("The actor cannot delete this role.")
        with managed_role_mutation():
            role.delete()
