class ScopedAccessConfigError(Exception):
    """Raised when the SCOPED_ACCESS configuration is invalid or inconsistent."""


class InvalidAssignmentTransitionError(ValueError):
    """Raised when an assignment lifecycle transition is not allowed."""


class AssignmentDeletionError(RuntimeError):
    """Raised when code tries to hard-delete assignment audit history."""


class RoleManagementPermissionError(PermissionError):
    """Raised when an actor cannot manage a role or delegated permission."""


class RoleAssignmentError(ValueError):
    """Raised when a custom role is assigned outside its owner's subtree."""


class RoleOwnershipError(ValueError):
    """Raised when a custom role has an invalid owner or owner level."""


class DirectRolePermissionMutationError(RuntimeError):
    """Raised when role permissions bypass the actor-aware role API."""


class AssignmentScopeError(ValueError):
    """Raised when an assignment's level and scope node are inconsistent."""


class AssignmentManagementPermissionError(PermissionError):
    """Raised when an actor cannot manage assignments at the target scope."""
