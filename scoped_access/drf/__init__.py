"""DRF glue (optional extra `[drf]`) — SPEC §5 HTTP mapping, §7, §10."""

try:
    import rest_framework  # noqa: F401
except ImportError as exc:
    raise ImportError(
        "scoped_access.drf needs djangorestframework. Install the extra: pip install django-scoped-access[drf]"
    ) from exc

from .mixins import ScopeQuerySetMixin, ScopeWriteGuardMixin
from .permissions import RequireReAuth, ScopedModelPermission, ScopeObjectPermission
from .throttling import ReAuthRateThrottle
from .views import MeAccessView, ReAuthView
from .viewsets import ScopedModelViewSet, ScopedReadOnlyModelViewSet

__all__ = [
    "MeAccessView",
    "ReAuthView",
    "ReAuthRateThrottle",
    "RequireReAuth",
    "ScopeObjectPermission",
    "ScopeQuerySetMixin",
    "ScopeWriteGuardMixin",
    "ScopedModelPermission",
    "ScopedModelViewSet",
    "ScopedReadOnlyModelViewSet",
]
