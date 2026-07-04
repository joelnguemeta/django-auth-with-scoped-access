"""QuerySet scoping for DRF viewsets (SPEC §4.3)."""

from __future__ import annotations

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
