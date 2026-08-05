from django.apps import AppConfig


class ScopedAccessConfig(AppConfig):
    name = "scoped_access"
    default_auto_field = "django.db.models.BigAutoField"
    verbose_name = "Scoped Access"

    def ready(self):
        from . import (
            checks,  # noqa: F401 — registers system checks
            role_permissions,  # noqa: F401 — protects M2M mutations
        )
        from .reauth.receivers import connect_password_change_receivers

        connect_password_change_receivers()
