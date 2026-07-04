"""Step-up re-authentication (optional extra `[reauth]`) — SPEC §7.

TODO (spec-first: a stateful conformance check format is needed first):
- ReAuthService (issue/consume/invalidate, cache-backed, single-use, TTL)
- Pluggable verifiers (password first; PIN/TOTP/WebAuthn later)
- RequireReAuth DRF permission + ReAuthView (X-ReAuth-Token contract)
"""
