"""Secure-by-default DRF ViewSets for scoped resources."""

from __future__ import annotations

from rest_framework import viewsets

from .mixins import ScopeQuerySetMixin, ScopeWriteGuardMixin
from .permissions import ScopedModelPermission, ScopeObjectPermission


class ScopedModelViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, viewsets.ModelViewSet):
    """ModelViewSet with the complete scoped-access security pipeline."""

    permission_classes = [ScopedModelPermission, ScopeObjectPermission]


class ScopedReadOnlyModelViewSet(ScopeQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    """Read-only ModelViewSet with model and object scope enforcement."""

    permission_classes = [ScopedModelPermission, ScopeObjectPermission]
