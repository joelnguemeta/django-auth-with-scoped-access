from django.contrib import admin

from scoped_access.admin import ScopedModelAdmin

from .models import Ticket


@admin.register(Ticket)
class TicketAdmin(ScopedModelAdmin):
    list_display = ["title", "team", "is_closed"]
    list_filter = ["is_closed"]
    search_fields = ["title"]
