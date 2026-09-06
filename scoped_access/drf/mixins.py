"""QuerySet scoping and write guard for DRF viewsets (SPEC §4.3, §5)."""

from __future__ import annotations

import copy
import warnings

from django.core.exceptions import FieldDoesNotExist
from rest_framework.exceptions import PermissionDenied

from .. import engine


def _required_scoped_permissions(request, view, model) -> tuple[str, ...]:
    """Return method permissions when the ViewSet uses ScopedModelPermission."""
    from .permissions import ScopedModelPermission

    for permission in getattr(view, "permission_classes", ()):
        permission_class = permission if isinstance(permission, type) else type(permission)
        if issubclass(permission_class, ScopedModelPermission):
            return tuple(permission_class().get_required_permissions(request.method, model))
    return ()


class ScopeQuerySetMixin:
    """Filters list responses to the caller's scope, at the database level.

    When paired with ``ScopedModelPermission``, only assignments containing
    the HTTP method's permission contribute to the filtered queryset.

    Add as FIRST parent of a ViewSet whose model is registered in the
    resource registry (or is itself a hierarchy node model)::

        class PatientViewSet(ScopeQuerySetMixin, ModelViewSet):
            ...

    Detail routes are intentionally NOT filtered here: they go through
    ScopeObjectPermission, which distinguishes 403 (out of scope) from 404.
    Set ``scope_filter_all_actions = True`` to hide out-of-scope objects
    entirely (404 instead of 403).
    """

    scope_filter_all_actions = False

    def get_queryset(self):
        self._warn_if_detail_routes_are_unprotected()
        qs = super().get_queryset()
        if not (self.scope_filter_all_actions or getattr(self, "action", None) == "list"):
            return qs
        permissions = _required_scoped_permissions(self.request, self, qs.model)
        if permissions:
            filters = engine.scope_filter_q(self.request.user, qs.model, permission=permissions[0])
            for permission in permissions[1:]:
                filters &= engine.scope_filter_q(self.request.user, qs.model, permission=permission)
        else:
            filters = engine.scope_filter_q(self.request.user, qs.model)
        return qs.filter(filters).distinct()

    def _warn_if_detail_routes_are_unprotected(self) -> None:
        """Warn when detail routes have neither filtering nor a scope gate."""
        if self.scope_filter_all_actions:
            return

        # Import lazily to keep the mixins module independent from the
        # permissions module during package initialization.
        from .permissions import ScopedModelPermission, ScopeObjectPermission

        permission_classes = getattr(self, "permission_classes", ())
        if any(
            isinstance(permission, type) and issubclass(permission, (ScopedModelPermission, ScopeObjectPermission))
            for permission in permission_classes
        ):
            return

        warnings.warn(
            f"{type(self).__name__} uses ScopeQuerySetMixin without ScopeObjectPermission; "
            "detail routes may expose out-of-scope objects. Add ScopeObjectPermission or set "
            "scope_filter_all_actions = True.",
            RuntimeWarning,
            stacklevel=2,
        )


def _apply_payload(serializer):
    """The instance as it would be persisted: a copy of the current one (or
    a blank model) with the validated concrete fields applied. M2M and
    reverse relations are skipped — they cannot anchor a resource. Relations
    written as nested payloads (dicts) resolve to no anchor, hence deny:
    handle those serializers manually.
    """
    model = serializer.Meta.model
    candidate = copy.copy(serializer.instance) if serializer.instance is not None else model()
    for name, value in serializer.validated_data.items():
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist:
            continue
        if field.many_to_many or field.one_to_many:
            continue
        setattr(candidate, name, value)
    return candidate


class ScopeWriteGuardMixin:
    """Write guard (SPEC §5): the object as it would be persisted — target
    anchor on create, the NEW anchor when a write moves the object — must
    fall inside the caller's scope, else 403.

    Complements ScopeObjectPermission, which only sees the object as stored:
    without this mixin a caller could create into, or move an object to, a
    scope they do not cover.

        class PatientViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, ModelViewSet):
            ...
    """

    def perform_create(self, serializer):
        self._assert_target_scope(serializer)
        super().perform_create(serializer)

    def perform_update(self, serializer):
        self._assert_target_scope(serializer)
        super().perform_update(serializer)

    def _assert_target_scope(self, serializer) -> None:
        candidate = _apply_payload(serializer)
        permissions = _required_scoped_permissions(self.request, self, serializer.Meta.model)
        allowed = (
            all(engine.has_perm(self.request.user, permission, candidate) for permission in permissions)
            if permissions
            else engine.user_covers(self.request.user, candidate)
        )
        if not allowed:
            raise PermissionDenied({"detail": "Target scope is outside your scope."})
