from rest_framework import serializers

from helpdesk.models import Ticket


class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = ["id", "team", "title", "body", "is_closed", "created_at"]
        read_only = ('created_at',)

