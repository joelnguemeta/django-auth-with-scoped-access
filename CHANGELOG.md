# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security
- **Role & Permission ORM Mutation Guards**: Guard `RolePermissionQuerySet.update()` and `bulk_update()` against actor-less mutations through public managers and related managers (`role.role_permissions`, `permission.scoped_role_permissions`). Additionally guard `RoleQuerySet.bulk_update()` and `ScopeAssignmentQuerySet.bulk_update()` to prevent bypassing `RoleService` and lifecycle state machines (#16).
- **Assignment Reactivation Anti-Escalation**: Enforce Rule **R7** anti-escalation (`can_assign_role`) when reactivating suspended role assignments (`reactivate()`). Prevents managers from restoring suspended assignments containing permissions they do not effectively hold at the target scope (#15).
- **Lifecycle Signal Consistency**: Make assignment lifecycle transitions and role permission changes transactional, invalidate request caches before emitting signals, and avoid serving memoized authorization decisions after transactional authority changes (#17).

### Fixed
- **DRF Dynamic Permissions**: Enforce permission-aware scoping in `ScopeQuerySetMixin` and `ScopeWriteGuardMixin` when permissions are provided dynamically via `get_permissions()`, preserving custom `perms_map` configurations and preventing recursion or premature token consumption (#14).

## [0.2.0] - 2026-09-05

### Added
- **DRF Scoped ViewSets**: `ScopedModelViewSet` and `ScopedReadOnlyModelViewSet` integrating `ScopedModelPermission`, `ScopeObjectPermission`, `ScopeQuerySetMixin`, and `ScopeWriteGuardMixin` out of the box.
- **Strict Resource Registration Mode**: `strict=True` on `register()` to enforce explicit parent relations and fail early on misconfigurations.

### Security
- Bind DRF method permissions and scope coverage to the same effective assignment for list, detail, create, and update operations.
- Prevent assignment managers from assigning roles whose permissions exceed their effective authority at the target scope.
- Make assignment grants transactional so signal failures cannot leave partially completed lifecycle operations.
- Apply a dedicated per-user throttle to the ReAuth credential endpoint, defaulting to `5/minute`.
- Atomically consume ReAuth tokens to prevent token reuse and race conditions.

## [0.1.1] - 2026-08-21

### Added
- **Security System Check (`scoped_access.W001`)**: Added a warning when `REAUTH` is enabled but the default Django cache backend is process-local (`LocMemCache` or `DummyCache`) rather than a shared distributed cache (Redis/Memcached).
- Documented `scoped_access.W001` in the system checks table in `docs/configuration.md`.

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
