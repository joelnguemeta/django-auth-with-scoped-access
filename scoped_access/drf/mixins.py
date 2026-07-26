"""QuerySet scoping and write guard for DRF viewsets (SPEC §4.3, §5)."""

from __future__ import annotations

import copy

from django.core.exceptions import FieldDoesNotExist
from rest_framework.exceptions import PermissionDenied

from .. import engine


class ScopeQuerySetMixin:
    """Filters list responses to the caller's scope, at the database level.

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
        qs = super().get_queryset()
        if not (self.scope_filter_all_actions or getattr(self, "action", None) == "list"):
            return qs
        return qs.filter(engine.scope_filter_q(self.request.user, qs.model)).distinct()


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
        if not engine.user_covers(self.request.user, _apply_payload(serializer)):
            raise PermissionDenied({"detail": "Target scope is outside your scope."})
