"""Hierarchy levels and resource anchors (SPEC §2, §4.1).

Two registries drive the engine:

- the **hierarchy** (from settings) — ordered levels, each optionally bound
  to a host model with a parent accessor;
- the **resource registry** — host models declare an *anchor*: the ORM path
  from a resource to its node, or explicitly opt into global access.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.apps import apps


@dataclass(frozen=True)
class Level:
    name: str
    model_label: str | None = None  # None = root level
    parent: str | None = None  # accessor to the previous modeled level
    discriminator: tuple = ()  # filter kwargs when several levels share a model

    @property
    def is_root(self) -> bool:
        return self.model_label is None

    @property
    def model(self):
        if self.model_label is None:
            return None
        return apps.get_model(self.model_label)

    def queryset(self):
        qs = self.model._default_manager.all()
        if self.discriminator:
            qs = qs.filter(**dict(self.discriminator))
        return qs


class Hierarchy:
    def __init__(self, levels: tuple[Level, ...]):
        self.levels = levels
        self._by_name = {lvl.name: lvl for lvl in levels}

    def __bool__(self) -> bool:
        return bool(self.levels)

    def level(self, name: str) -> Level:
        return self._by_name[name]

    def rank(self, name: str) -> int:
        """Index in the hierarchy — 0 is the top (SPEC §2)."""
        return self.levels.index(self._by_name[name])

    def is_root(self, name: str | None) -> bool:
        return name is not None and self._by_name[name].is_root

    def levels_for_model(self, model) -> list[Level]:
        return [lvl for lvl in self.levels if not lvl.is_root and lvl.model is model]

    def is_node_model(self, model) -> bool:
        return bool(self.levels_for_model(model))

    def parent_accessor_for_model(self, model) -> str | None:
        """Accessor used to walk up from an instance of `model`.

        Levels sharing one model must share one parent accessor; the walk
        stops naturally on a null reference (e.g. a top-level node).
        """
        for lvl in self.levels_for_model(model):
            if lvl.parent:
                return lvl.parent
        return None


class ResourceRegistry:
    """Maps host resource models to their anchor path."""

    def __init__(self):
        self._anchors: dict[type, str] = {}
        self._globals: set[type] = set()

    def register(self, model, *, anchor: str) -> None:
        self._anchors[model] = anchor
        self._globals.discard(model)

    def register_global(self, model) -> None:
        """Mark a model as intentionally global rather than unregistered."""
        self._anchors.pop(model, None)
        self._globals.add(model)

    def unregister(self, model) -> None:
        self._anchors.pop(model, None)
        self._globals.discard(model)

    def clear(self) -> None:
        self._anchors.clear()
        self._globals.clear()

    def anchor_for(self, model) -> str | None:
        return self._anchors.get(model)

    def is_registered(self, model) -> bool:
        return model in self._anchors or model in self._globals

    def is_global(self, model) -> bool:
        return model in self._globals

    def items(self):
        """(model, anchor) pairs — read-only view for introspection/checks."""
        return self._anchors.items()

    def models(self) -> set[type]:
        """Return every explicitly anchored or global model."""
        return set(self._anchors) | self._globals


resources = ResourceRegistry()


def register(model, *, anchor: str) -> None:
    """Public API: `scoped_access.registry.register(Patient, anchor="department")`."""
    resources.register(model, anchor=anchor)


def register_global(model) -> None:
    """Public API: explicitly declare a model as globally scoped."""
    resources.register_global(model)
