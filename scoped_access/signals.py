"""Lifecycle events (SPEC §9).

The package emits; the host application subscribes (auditing, cache
invalidation, notifications). The package itself persists no audit log.
"""

from django.dispatch import Signal

# kwargs: assignment, actor
assignment_granted = Signal()
# kwargs: assignment, actor, reason
assignment_suspended = Signal()
assignment_reactivated = Signal()
assignment_revoked = Signal()
# kwargs: role, added (list[str]), removed (list[str]), actor
role_permissions_changed = Signal()
# kwargs: user (never the token value)
reauth_issued = Signal()
reauth_consumed = Signal()
reauth_failed = Signal()
