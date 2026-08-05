"""Guard the role-permission M2M against actor-less direct mutations."""

from __future__ import annotations

import contextvars
from contextlib import contextmanager

from django.db.models.signals import m2m_changed
from django.dispatch import receiver

from .exceptions import DirectRolePermissionMutationError

_managed_mutation = contextvars.ContextVar("scoped_access_role_permission_mutation", default=False)


@contextmanager
def managed_role_permission_mutation():
    """Allow an already-authorized mutation from the role lifecycle API."""
    token = _managed_mutation.set(True)
    try:
        yield
    finally:
        _managed_mutation.reset(token)


@receiver(m2m_changed, sender="scoped_access.RolePermission")
def reject_direct_role_permission_mutation(sender, action, **kwargs):
    """Reject add/remove/set/clear calls that have no attributable actor."""
    if action.startswith("pre_") and not _managed_mutation.get():
        raise DirectRolePermissionMutationError(
            "Use role.grant_permissions(..., by=actor) or role.revoke_permissions(..., by=actor)."
        )
