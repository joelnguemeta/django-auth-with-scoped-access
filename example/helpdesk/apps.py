from django.apps import AppConfig


class HelpdeskConfig(AppConfig):
    name = 'helpdesk'

    def ready(self):
        from scoped_access.registry import register
        from helpdesk.models import Ticket

        register(Ticket, anchor='team')