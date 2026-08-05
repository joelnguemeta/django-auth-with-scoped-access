"""Generic materialization targets for conformance cases.

One self-referencing `Node` model plays every hierarchy level (levels share
the model and are told apart by the `level` discriminator field), so any
fixture hierarchy — depth 1 to N — maps onto it.
"""

from django.db import models


class Node(models.Model):
    slug = models.SlugField(unique=True)
    level = models.CharField(max_length=50)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE, related_name="children")

    def __str__(self) -> str:
        return f"{self.slug} ({self.level})"


class Resource(models.Model):
    """Registered resource: anchored to a node (SPEC §4.1)."""

    slug = models.SlugField(unique=True)
    anchor = models.ForeignKey(Node, null=True, blank=True, on_delete=models.CASCADE, related_name="+")


class GlobalThing(models.Model):
    """Unregistered model = global resource (skips the scope check only)."""

    slug = models.SlugField(unique=True)
