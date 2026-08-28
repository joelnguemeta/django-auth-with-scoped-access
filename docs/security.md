# Security Guide & Threat Model

This document outlines the security architecture, threat model, defenses, and production deployment recommendations for **Django Scoped Access**.

---

## 1. Threat Model, Assumptions & Security Boundaries

### What the library protects

Django Scoped Access is designed to protect trusted Django applications against:

- unauthorized external clients reaching APIs, views, and admin workflows that use the library's authorization integration;
- cross-tenant object access, scope injection, and privilege delegation beyond the caller's effective authority;
- accidental developer mistakes in ordinary application code, such as direct assignment mutation or an incomplete DRF ViewSet configuration;
- concurrent ReAuth token reuse and stale authorization state handled through the documented database and cache paths.

### Trust assumptions

The security guarantees assume that:

- Django authentication supplies the correct active principal and the application invokes authorization before releasing or mutating protected data;
- the database, shared cache, operating system, deployment credentials, and application startup configuration are trusted;
- resource and global-model registrations run during application startup, before traffic is accepted;
- custom authentication backends, ReAuth verifiers, cache backends, serializers, and permission policies honor their documented contracts.

### Out of scope

Python does not provide an in-process sandbox. Code that is hostile or already compromised inside the Django process can bypass high-level safeguards by using raw SQL, private managers such as `Model._base_manager`, monkey-patching, importing internal mutation contexts, or calling the database directly. Likewise, a database administrator or attacker holding database credentials with broader privileges can modify authorization state outside the library.

The library also cannot protect endpoints that omit its permission checks, query paths that never call the engine, compromised infrastructure, credential theft, transport-layer attacks, or sensitive values written to application logs. Use code review, tests, least-privilege deployment credentials, database auditing, TLS, secret management, and platform-level monitoring as complementary controls.

## 2. Threats & Defenses

### Threat 1: Cross-Tenant Data Access (IDOR / BOLA)
- **Attack**: A user authorized in *Organization A* attempts to access or mutate resources in *Organization B* by manipulating resource IDs in REST URLs (`GET /api/patients/999/`).
- **Defenses**:
  1. `ScopeQuerySetMixin` filters collections in SQL so foreign tenant objects are never returned.
  2. `ScopeObjectPermission` checks individual instances on detail endpoints against `engine.user_covers()`.
  3. `ScopeWriteGuardMixin` intercepts create/update mutations to verify that the **target scope** belongs to the caller.

---

### Threat 2: Privilege Escalation via Custom Roles (Anti-Escalation R5)
- **Attack**: A local tenant administrator creates a custom role containing global administrative permissions (`"accounts.delete_organization"`) or assigns themselves elevated privileges.
- **Defenses**:
  1. When `GRANTABLE_PERMISSIONS = "self"`, `can_grant_permission()` enforces that an actor cannot add any permission to a role unless the actor holds that permission effectively at the role's owner scope.
  2. Custom roles cannot be assigned at root scope or outside their owner's subtree (Rule R2).

---

### Threat 3: Circumventing Lifecycle Audit Trails
- **Attack**: An application bug or exposed endpoint attempts to hard-delete or bulk-modify assignments through the normal ORM surface (`ScopeAssignment.objects.filter(...).delete()`).
- **Defenses**:
  1. `AbstractScopeAssignment.delete()` raises `AssignmentDeletionError`. Assignments must be terminated via `.revoke()`.
  2. Direct mutations without managed context tokens (`managed_assignment_mutation()`) raise `DirectAssignmentMutationError`.
  3. Transitions between `ACTIVE`, `SUSPENDED`, and `REVOKED` are guarded by atomic SQL conditional updates.

These are application guardrails, not a sandbox against hostile in-process Python or direct database access. Revoke `DELETE` from the production runtime database role as described below when immutable assignment history is required.

---

### Threat 4: Step-Up Token Reuse or Hijacking
- **Attack**: An attacker captures a ReAuth token from logs or network traffic and attempts to reuse it across multiple endpoints or for another user account.
- **Defenses**:
  1. **Single-Use**: Tokens are checked and deleted from cache on consumption.
  2. **Generation Invalidation**: Password changes invalidate all active tokens for that user immediately.
  3. **Strict Binding**: Tokens are bound to the specific `user_id`. Foreign user mismatches fail closed without consuming the token.
  4. **Superusers Gated**: Superusers are never exempt from `RequireReAuth`.

---

## 3. Production Security Checklist

### 1. Configure Throttling on ReAuth Endpoint
Protect `POST /api/auth/reauth/` against brute-force attacks with a dedicated, authenticated-user throttle. Defining a rate alone is insufficient; the endpoint must also attach a throttle using that scope:

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_RATES": {
        "scoped_access_reauth": "5/minute",
    },
}
```

```python
# views.py
from rest_framework.throttling import ScopedRateThrottle
from scoped_access.drf import ReAuthView


class ThrottledReAuthView(ReAuthView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scoped_access_reauth"
```

Also rate-limit by source IP at the reverse proxy or API gateway. DRF's built-in throttles are useful application controls, but they are not a denial-of-service defense and may allow short bursts.

---

### 2. Use a Shared Cache Backend for ReAuth
In multi-worker or containerized deployments (Kubernetes, AWS ECS, Gunicorn/Uvicorn), do **not** use `LocMemCache` or `DummyCache`. Configure a shared Redis or Memcached backend:

```python
# settings.py
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}
```

When `REAUTH.ENABLED=True`, Django Scoped Access emits system check `scoped_access.W001` if the default cache is process-local. Treat this warning as production-blocking for Kubernetes: a pod-local cache can reject valid tokens on a different pod and can leave password-change invalidation incomplete across pods.

ReAuth consumption is atomic under concurrent requests: Redis uses `GETDEL` or Lua, while other Django backends use an atomic `cache.add()` claim. If you provide a custom cache backend, verify that its `add()` implementation is genuinely atomic across workers.

---

### 3. Start DRF Endpoints from the Unified ViewSets
Prefer the secure-by-default base class so model permissions, detail-object scope checks, list filtering, and write guards remain together:

```python
from scoped_access.drf import ScopedModelViewSet


class PatientViewSet(ScopedModelViewSet):
    queryset = Patient.objects.all()
    serializer_class = PatientSerializer
```

If composing mixins manually, pair `ScopeQuerySetMixin` with `ScopeObjectPermission`, and add `ScopeWriteGuardMixin` to writable ViewSets.

---

### 4. Enable Per-Request Cache Middleware
Reduce SQL query volume while maintaining strict revocation guarantees:

```python
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "scoped_access.cache.ScopedAccessCacheMiddleware",
]
```

---

### 5. Restrict the Runtime Database Role

Use separate database roles for migrations/operations and for the running application. The runtime role needs to update assignment rows for lifecycle transitions, but it should not be able to hard-delete the audit trail.

For PostgreSQL with the default assignment model and a runtime role named `app_runtime`:

```sql
REVOKE DELETE ON TABLE scoped_access_scopeassignment FROM app_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE scoped_access_scopeassignment TO app_runtime;
```

Adjust the table and role names when using a swapped assignment model. Audit inherited roles, schema grants, ownership, and `PUBLIC` privileges too: a `REVOKE` on one direct grant is ineffective if the runtime principal inherits `DELETE` through another role. Keep migration credentials out of application containers and verify the effective permissions in deployment tests.

Database permissions reduce the impact of raw SQL executed with the runtime credentials. They do not protect against a database owner, superuser, compromised migration credential, or another principal that retains broader grants.

---

### 6. Protect ReAuth Tokens and Audit Security Events

- Require TLS from the client through the trusted ingress path.
- Never place `X-ReAuth-Token` values, passwords, or verifier proofs in logs, traces, analytics, or error reports.
- Restrict access to the shared cache and isolate its keyspace from untrusted applications.
- Monitor ReAuth failure signals, role changes, assignment lifecycle events, system-check failures, and unexpected database permission errors.
