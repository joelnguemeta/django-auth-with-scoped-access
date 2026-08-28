# Security Guide & Threat Model

This document outlines the security architecture, threat model, defenses, and production deployment recommendations for **Django Scoped Access**.

---

## 1. Threat Model & Defenses

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
- **Attack**: A rogue developer or compromised endpoint attempts to hard-delete or bulk-modify assignments via direct ORM calls (`ScopeAssignment.objects.filter(...).delete()`).
- **Defenses**:
  1. `AbstractScopeAssignment.delete()` raises `AssignmentDeletionError`. Assignments must be terminated via `.revoke()`.
  2. Direct mutations without managed context tokens (`managed_assignment_mutation()`) raise `DirectAssignmentMutationError`.
  3. Transitions between `ACTIVE`, `SUSPENDED`, and `REVOKED` are guarded by atomic SQL conditional updates.

---

### Threat 4: Step-Up Token Reuse or Hijacking
- **Attack**: An attacker captures a ReAuth token from logs or network traffic and attempts to reuse it across multiple endpoints or for another user account.
- **Defenses**:
  1. **Single-Use**: Tokens are checked and deleted from cache on consumption.
  2. **Generation Invalidation**: Password changes invalidate all active tokens for that user immediately.
  3. **Strict Binding**: Tokens are bound to the specific `user_id`. Foreign user mismatches fail closed without consuming the token.
  4. **Superusers Gated**: Superusers are never exempt from `RequireReAuth`.

---

## 2. Production Security Checklist

### 1. Configure Throttling on ReAuth Endpoint
Protect `POST /api/auth/reauth/` against brute-force attacks by enabling Django REST Framework rate limiting:

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/day",
        "user": "1000/day",
        "scoped_access_reauth": "5/minute",
    },
}
```

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

### 3. Pair `ScopeQuerySetMixin` with `ScopeObjectPermission`
When writing ViewSets:

```python
# ✅ SECURE: Both list and detail actions are protected
class PatientViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, ModelViewSet):
    queryset = Patient.objects.all()
    serializer_class = PatientSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]
```

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
