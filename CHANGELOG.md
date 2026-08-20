# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-08-20

### Added
- Reference implementation of the **Scoped Access Specification** (`SPEC.md`).
- **Hierarchy Engine**: Declarative hierarchy configuration supporting arbitrary tree depth, parent accessors, and model discriminators.
- **Resource Registry**: Declarative anchoring mechanism connecting domain models to hierarchy nodes.
- **RBAC & Multi-Tenant Scoping**: Support for universal system roles and tenant-owned custom roles.
- **Anti-Escalation (Rule R5)**: Strict checks preventing role managers from granting permissions they do not effectively hold.
- **Assignment Lifecycle**: State machine (`ACTIVE` ⇄ `SUSPENDED` → `REVOKED`) with immutable audit trails and temporal validity (`valid_from` / `valid_until`).
- **Step-Up Re-Authentication (ReAuth)**: Single-use, time-limited tokens with pluggable verifiers (password, PIN, TOTP, WebAuthn) and automatic invalidation on password changes.
- **Django REST Framework (DRF) Integration**:
  - `ScopedModelPermission`: Method-to-permission mapping with strict read-access enforcement.
  - `ScopeObjectPermission`: Object-level scope verification.
  - `ScopeQuerySetMixin`: Database-level SQL filtering for collection endpoints.
  - `ScopeWriteGuardMixin`: Target-scope validation on create/update mutations to prevent scope injection.
  - `RequireReAuth`: Gated action permission requiring a valid `X-ReAuth-Token`.
  - `MeAccessView`: Standard `GET /me/access/` introspection endpoint.
  - `ReAuthView`: Standard `POST /auth/reauth/` credential exchange view.
- **Django Authentication Backend**: `ScopedPermissionBackend` integrating with `user.has_perm()` and Django Admin.
- **Per-Request Caching**: ContextVar-backed `ScopedAccessCacheMiddleware` with in-request lifecycle invalidation.
- **Swappable Models**: Support for customizing `Role` (`SCOPED_ACCESS_ROLE_MODEL`) and `ScopeAssignment` (`SCOPED_ACCESS_ASSIGNMENT_MODEL`).
- **Django System Checks**: Comprehensive startup validation of hierarchy and settings consistency.
- **Language-Agnostic Conformance Test Suite**: 100% test pass rate across 102 test cases.
- **Complete Documentation**: Full Material for MkDocs suite with guides, tutorials, threat model, and API references.
