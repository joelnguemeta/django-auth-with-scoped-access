from django.apps import AppConfig


class HelpdeskConfig(AppConfig):
    name = "helpdesk"

    def ready(self):
        from helpdesk.models import Ticket
        from scoped_access.registry import register

        register(Ticket, anchor="team")
