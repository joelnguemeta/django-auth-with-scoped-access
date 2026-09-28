# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Documentation
- Fix rendering on Read the Docs: GitHub-style alerts and LaTeX formulas showed as raw text.
- New Python API reference page (engine, registry, services, assignments, ReAuth, exceptions) and a Changelog page.
- Django guide: list examples now filter by permission (`visible_resources(..., permission=...)`); warn that `has_perm()` without an object means "held anywhere"; new scoped Django admin section.
- Document the `manage_roles` / `manage_global_roles` / `manage_assignments` administration permissions, root and flat-RBAC grants, and every lifecycle and ReAuth signal.
- ReAuth: document the endpoint contract, and warn that `RequireReAuth` is a no-op while `REAUTH.ENABLED` is `False`.
- Swappable models: the example now declares the required `permissions` and `indexes`.
- Pin MkDocs below 2.0, which Material for MkDocs does not support.

## [0.3.0] - 2026-09-28

First PyPI release since 0.1.1: it also ships everything listed under 0.2.0, which was never published.

### Security
- Prevent recursive dynamic DRF permission discovery from caching incomplete policies; return an empty queryset during discovery and propagate discovery errors.
- Share cache invalidation state across nested request-cache contexts so revocations and transaction rollbacks remain visible.
- Re-read and lock roles before management and assignment mutations to prevent stale owners or prefetched permissions from bypassing authorization.
- Enforce scoped permissions inside DRF AND compositions; reject scoped OR/NOT compositions that cannot be represented by the mixins' filters.
- Re-evaluate assignment activation and expiry at every cached authorization read.
- **Role & Permission ORM Mutation Guards**: Guard `RolePermissionQuerySet.update()` and `bulk_update()` against actor-less mutations through public managers and related managers (`role.role_permissions`, `permission.scoped_role_permissions`). Additionally guard `RoleQuerySet.bulk_update()` and `ScopeAssignmentQuerySet.bulk_update()` to prevent bypassing `RoleService` and lifecycle state machines (#16).
- **Assignment Reactivation Anti-Escalation**: Enforce Rule **R7** anti-escalation (`can_assign_role`) when reactivating suspended role assignments (`reactivate()`). Prevents managers from restoring suspended assignments containing permissions they do not effectively hold at the target scope (#15).
- **Lifecycle Signal Consistency**: Make assignment lifecycle transitions and role permission changes transactional, invalidate request caches before emitting signals, and avoid serving memoized authorization decisions after transactional authority changes (#17).

### Fixed
- **DRF Dynamic Permissions**: Enforce permission-aware scoping in `ScopeQuerySetMixin` and `ScopeWriteGuardMixin` when permissions are provided dynamically via `get_permissions()`, preserving custom `perms_map` configurations and preventing recursion or premature token consumption (#14).
- Declare Django 5.2/6.0 and Python 3.14 support in package metadata to match the CI matrix; drop untested Django 5.0/5.1 classifiers.
- Clarify that only the password ReAuth verifier ships built in; PIN, TOTP and WebAuthn are host-provided verifiers.
- Correct the documented `ScopeAssignment` import, make the helpdesk seed safe to rerun, and align the specification and conformance documentation with strict registration.

## [0.2.0] - 2026-09-05

Tagged in the changelog but never published to PyPI; shipped as part of 0.3.0.

### Added
- **DRF Scoped ViewSets**: `ScopedModelViewSet` and `ScopedReadOnlyModelViewSet` integrating `ScopedModelPermission`, `ScopeObjectPermission`, `ScopeQuerySetMixin`, and `ScopeWriteGuardMixin` out of the box.
- **Strict Resource Registration Mode**: `SCOPED_ACCESS["STRICT_REGISTRATION"] = True` denies unregistered resources to non-superusers; `register_global()` explicitly marks global models.

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
- **Language-Agnostic Conformance Test Suite**: Shared JSON cases for authorization and ReAuth, with a Django reference adapter.
- **Complete Documentation**: Full Material for MkDocs suite with guides, tutorials, threat model, and API references.
