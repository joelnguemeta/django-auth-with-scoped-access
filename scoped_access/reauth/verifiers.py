"""Pluggable step-up proofs (SPEC §7.1).

v1 ships the password verifier. Hosts register their own (PIN, TOTP,
WebAuthn…) at startup:

    from scoped_access.reauth import verifiers

    class PinVerifier:
        name = "pin"
        def verify(self, user, *, pin=None, **_):
            return check_pin(user, pin)

    verifiers.register(PinVerifier())
"""

from __future__ import annotations


class PasswordVerifier:
    name = "password"

    def verify(self, user, *, password: str | None = None, **_) -> bool:
        return bool(password) and user.check_password(password)


_VERIFIERS: dict[str, object] = {}


def register(verifier) -> None:
    _VERIFIERS[verifier.name] = verifier


def get(name: str):
    return _VERIFIERS.get(name)


register(PasswordVerifier())
