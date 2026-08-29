"""DRF permission classes (SPEC §5 HTTP mapping, §7 step-up)."""

from __future__ import annotations

from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission, DjangoModelPermissions

from .. import engine
from ..conf import get_config
from ..reauth import ReAuthService


class ScopedModelPermission(DjangoModelPermissions):
    """HTTP method → model permission, read included (SPEC §5).

    Unlike stock DjangoModelPermissions, GET/HEAD require `view_*`:
    there is no anonymous-read default.
    """

    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": ["%(app_label)s.view_%(model_name)s"],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_object_permission(self, request, view, obj) -> bool:
        """Bind the HTTP permission and scope decision to one assignment."""
        permissions = self.get_required_permissions(request.method, type(obj))
        if all(engine.has_perm(request.user, permission, obj) for permission in permissions):
            return True
        raise PermissionDenied({"detail": "You do not have this permission in the object's scope."})


class ScopeObjectPermission(BasePermission):
    """Object-level scope check (SPEC §4.2) — pair with ScopedModelPermission."""

    def has_object_permission(self, request, view, obj) -> bool:
        if engine.user_covers(request.user, obj):
            return True
        raise PermissionDenied({"detail": "This object is outside your scope."})


class ReAuthRequired(PermissionDenied):
    """403 with a machine-readable body (SPEC §7.3) so clients can trigger
    the step-up flow. `detail` is set after init: DRF's ErrorDetail coercion
    would otherwise turn the boolean into the string 'True'.
    """

    def __init__(self):
        super().__init__()
        self.detail = {
            "detail": "Re-authentication required for this action.",
            "reauth_required": True,
        }


class RequireReAuth(BasePermission):
    """Step-up gate (SPEC §7): expects a single-use token in X-ReAuth-Token.

    Evaluated in addition to — never instead of — the permission checks.
    Superusers are NOT exempt.
    """

    def has_permission(self, request, view) -> bool:
        if not get_config().reauth.get("ENABLED"):
            return True
        token = request.headers.get("X-ReAuth-Token")
        if not ReAuthService.consume(token, request.user):
            raise ReAuthRequired
        return True
