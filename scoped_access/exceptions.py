class ScopedAccessConfigError(Exception):
    """Raised when the SCOPED_ACCESS configuration is invalid or inconsistent."""


class InvalidAssignmentTransitionError(ValueError):
    """Raised when an assignment lifecycle transition is not allowed."""


class AssignmentDeletionError(RuntimeError):
    """Raised when code tries to hard-delete assignment audit history."""
