"""Organization -> Team -> Ticket. Ticket is the only registered resource;
Organization/Team are hierarchy nodes referenced by SCOPED_ACCESS.HIERARCHY.
"""
from django.db import models

class Organization(models.Model):
    name = models.CharField(max_length=100)
    plan = models.CharField(max_length=20, default='free') # billing plan — see ReAuth-gated view

    class Meta:
        db_table = "organization"

    def __str__(self) -> str:
        return self.name


class Team(models.Model):
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="teams")
    name = models.CharField(max_length=200)

    class Meta:
        db_table = "team"
        unique_together = ('organization', 'name')

    def __str__(self) -> str:
        return self.name


class Ticket(models.Model):
    team = models.ForeignKey(
        Team, on_delete=models.CASCADE, related_name="tickets")
    title = models.CharField(max_length=255)
    body = models.TextField(blank=True)
    is_closed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ticket"

    def __str__(self) -> str:
        return self.title