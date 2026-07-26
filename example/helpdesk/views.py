from rest_framework import viewsets

from helpdesk.models import Ticket
from helpdesk.serializers import TicketSerializer
from scoped_access.drf import (
    RequireReAuth,
    ScopedModelPermission,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
    ScopeWriteGuardMixin,
)


class TicketViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, viewsets.ModelViewSet):
    queryset = Ticket.objects.select_related("team__organization")
    serializer_class = TicketSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action == "destroy":
            permissions.append(RequireReAuth())
        return permissions
