from rest_framework import viewsets

from helpdesk.models import Ticket
from helpdesk.serializers import TicketSerializer
from scoped_access import engine
from scoped_access.drf import ScopeQuerySetMixin, ScopedModelPermission, ScopeObjectPermission
from scoped_access.drf.permissions import RequireReAuth


class TicketViewSet(ScopeQuerySetMixin, viewsets.ModelViewSet):
    queryset = Ticket.objects.select_related("team__organization")
    serializer_class = TicketSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]

    def perform_create(self, serializer):
        team = serializer.validated_data["team"]
        if not engine.user_covers(self.request.user, team):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied
        serializer.save()

    def destroy(self, request, *args, **kwargs):
        RequireReAuth().has_permission(request, self)
        return super().destroy(request, *args, **kwargs)