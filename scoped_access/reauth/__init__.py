"""Step-up re-authentication (optional extra) — SPEC §7.

Framework-agnostic core: `ReAuthService` + pluggable `verifiers`.
The HTTP contract (X-ReAuth-Token, /auth/reauth/) lives in `scoped_access.drf`.
"""

from .service import ReAuthService
from .verifiers import register as register_verifier

__all__ = ["ReAuthService", "register_verifier"]
