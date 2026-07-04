"""Django authentication backend (design decision: backend, not User override).

Add to settings:

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",   # credentials
        "scoped_access.backends.ScopedPermissionBackend",  # authorization
    ]

`user.has_perm("app.codename", obj)` then works everywhere, including the
Django admin, without requiring a specific User model.
"""

from __future__ import annotations

from django.contrib.auth.backends import BaseBackend

from . import engine


class ScopedPermissionBackend(BaseBackend):
    def authenticate(self, request, **credentials):
        return None  # authorization only — credentials belong to another backend

    def has_perm(self, user_obj, perm, obj=None):
        return engine.has_perm(user_obj, perm, obj)

    def get_all_permissions(self, user_obj, obj=None):
        return engine.user_permissions(user_obj, obj)

    def has_module_perms(self, user_obj, app_label):
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        return any(p.startswith(f"{app_label}.") for p in engine.user_permissions(user_obj))
