"""Django admin glue: scoped change lists, object checks and write guard.

The stock ModelAdmin never filters rows by scope and asks `has_perm()`
without the object for change/delete: a permission held in one scope would
apply in every scope. ScopedModelAdmin applies the SPEC §5 rules instead.

    from scoped_access.admin import ScopedModelAdmin

    @admin.register(Ticket)
    class TicketAdmin(ScopedModelAdmin):
        list_display = ["title", "team"]

No permission implies another (SPEC §5): a row appears in the change list
only where the user holds `view_*`, even if they hold `change_*` there.
Inlines are not scoped; give their models their own ScopedModelAdmin.
"""

from __future__ import annotations

from django.contrib import admin
from django.contrib.auth import get_permission_codename
from django.core.exceptions import PermissionDenied
from django.db.models import Q

from . import engine
from .conf import get_config
from .registry import resources


def _perm(opts, action: str) -> str:
    return f"{opts.app_label}.{get_permission_codename(action, opts)}"


class ScopedModelAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        # pk__in instead of distinct(): multi-valued anchors may duplicate rows.
        allowed = self.model._default_manager.filter(
            engine.scope_filter_q(request.user, self.model, permission=_perm(self.opts, "view"))
        )
        return super().get_queryset(request).filter(pk__in=allowed.values("pk"))

    def has_view_permission(self, request, obj=None):
        if obj is None:
            return super().has_view_permission(request)
        return request.user.has_perm(_perm(self.opts, "view"), obj)

    def has_change_permission(self, request, obj=None):
        if obj is None:
            return super().has_change_permission(request)
        return request.user.has_perm(_perm(self.opts, "change"), obj)

    def has_delete_permission(self, request, obj=None):
        if obj is None:
            return super().has_delete_permission(request)
        return request.user.has_perm(_perm(self.opts, "delete"), obj)

    def save_model(self, request, obj, form, change):
        # Write guard: the object as it will be saved (new anchor) and, on
        # edit, as stored. list_editable saves without an object-level check.
        perm = _perm(self.opts, "change" if change else "add")
        if not request.user.has_perm(perm, obj):
            raise PermissionDenied("Target scope is outside your scope.")
        if change:
            stored = self.model._default_manager.filter(pk=obj.pk).first()
            if stored is None or not request.user.has_perm(perm, stored):
                raise PermissionDenied("This object is outside your scope.")
        super().save_model(request, obj, form, change)

    def delete_queryset(self, request, queryset):
        # Bulk delete ("delete_selected") only checks the permission without objects.
        deletable = engine.scope_filter_q(request.user, self.model, permission=_perm(self.opts, "delete"))
        if queryset.exclude(pk__in=self.model._default_manager.filter(deletable).values("pk")).exists():
            raise PermissionDenied("Some selected objects are outside your scope.")
        super().delete_queryset(request, queryset)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if "queryset" not in kwargs:
            choices = self._scoped_choices(request, db_field.related_model)
            if choices is not None:
                kwargs["queryset"] = choices
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def _scoped_choices(self, request, related):
        """Hierarchy nodes where the user may add or change this model, or
        registered resources they may view. Other models are left alone.
        The save-time write guard stays the enforcement point.
        """
        user = request.user
        levels = get_config().hierarchy.levels_for_model(related)
        if levels:
            q = Q(pk__in=[])
            for level in levels:
                for action in ("add", "change"):
                    nodes = engine.accessible_nodes(user, level.name, permission=_perm(self.opts, action))
                    q |= Q(pk__in=nodes.values("pk"))
            return related._default_manager.filter(q)
        if resources.anchor_for(related) is not None:
            return engine.visible_resources(user, related, permission=_perm(related._meta, "view"))
        return None
