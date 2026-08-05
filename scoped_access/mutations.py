"""Internal contexts identifying actor-aware model mutations."""

from __future__ import annotations

import contextvars
from contextlib import contextmanager

_role_mutation = contextvars.ContextVar("scoped_access_role_mutation", default=False)
_assignment_mutation = contextvars.ContextVar("scoped_access_assignment_mutation", default=False)


@contextmanager
def managed_role_mutation():
    token = _role_mutation.set(True)
    try:
        yield
    finally:
        _role_mutation.reset(token)


def role_mutation_is_managed() -> bool:
    return _role_mutation.get()


@contextmanager
def managed_assignment_mutation():
    token = _assignment_mutation.set(True)
    try:
        yield
    finally:
        _assignment_mutation.reset(token)


def assignment_mutation_is_managed() -> bool:
    return _assignment_mutation.get()
