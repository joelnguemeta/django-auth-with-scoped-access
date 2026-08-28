# Step-Up Re-Authentication (ReAuth)

**Step-Up Re-Authentication** requires users to provide fresh proof of identity (password, PIN, WebAuthn, TOTP) before performing high-risk actions (e.g., executing financial transfers, exporting sensitive medical data, deleting resources, or modifying role permissions).

---

## 1. How ReAuth Works

```
  Client (Browser / App)                       Server (Django API)
     │                                                │
     │ 1. DELETE /api/tickets/123/                    │
     ├───────────────────────────────────────────────►│ Gated by RequireReAuth
     │                                                │
     │ 2. 403 {"reauth_required": true}               │
     │◄───────────────────────────────────────────────┤ Client detects reauth prompt
     │                                                │
     │ 3. POST /api/auth/reauth/ {password: "..."}    │
     ├───────────────────────────────────────────────►│ Verifies credentials
     │                                                │ Issues single-use token (TTL: 300s)
     │ 4. 200 {"reauth_token": "abc123xyz"}           │
     │◄───────────────────────────────────────────────┤
     │                                                │
     │ 5. DELETE /api/tickets/123/                    │
     │    Header: X-ReAuth-Token: abc123xyz           │
     ├───────────────────────────────────────────────►│ Validates & burns token
     │                                                │
     │ 6. 204 No Content                              │
     │◄───────────────────────────────────────────────┤ Action executed successfully
```

---

## 2. Enabling ReAuth in Settings

Enable the ReAuth module and configure the token TTL (in seconds) in `settings.py`:

```python
# settings.py
SCOPED_ACCESS = {
    ...
    "REAUTH": {
        "ENABLED": True,
        "TTL": 300,  # 5 minutes
    }
}
```

---

## 3. Protecting Endpoints with `RequireReAuth`

Attach `RequireReAuth` to any DRF view or specific action:

```python
from scoped_access.drf import RequireReAuth

class OrganizationBillingViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, RequireReAuth]
```

Or for a specific action in a ViewSet:

```python
class TicketViewSet(ModelViewSet):
    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ("destroy", "export_phi"):
            permissions.append(RequireReAuth())
        return permissions
```

> [!IMPORTANT]
> **Superusers Are NOT Exempt**: Superusers must also provide a valid ReAuth token when accessing views protected by `RequireReAuth`.

---

## 4. Custom Verifiers (PIN, TOTP, WebAuthn)

Django Scoped Access ships with a built-in `password` verifier and provides a pluggable verifier registry for multi-factor authentication (MFA).

### Creating a Custom Verifier

Implement the `verify(self, user, **credentials) -> bool` protocol and register it:

```python
# myapp/verifiers.py
from scoped_access.reauth import verifiers

class TotpVerifier:
    name = "totp"

    def verify(self, user, *, code: str | None = None, **kwargs) -> bool:
        if not code:
            return False
        return user.totp_device.verify_token(code)

verifiers.register(TotpVerifier())
```

### Requesting a Token with a Custom Verifier

```bash
curl -X POST https://api.example.com/api/auth/reauth/ \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"verifier": "totp", "code": "123456"}'
```

---

## 5. Security & Invalidation Guarantees

- **Single-Use**: Tokens are burned upon first successful consumption or upon expiration.
- **Foreign-Principal Miss**: Presenting token $T$ minted for User A while authenticating as User B fails closed without burning User A's token.
- **Automatic Invalidation on Password Change**: When a user's password changes, all active ReAuth tokens for that user are immediately invalidated across all workers via generation counters.
- **Distributed Cache Backend**: In production, ensure `django.core.cache` uses a shared cache backend (for example Redis or Memcached) across all application servers.

> [!WARNING]
> In Kubernetes, ECS, or any multi-worker deployment, do **not** use `LocMemCache` or `DummyCache` for ReAuth. `LocMemCache` is local to each process/pod: a token issued by pod A may be rejected by pod B, and password-change invalidation may not reach every pod. When `REAUTH.ENABLED=True`, Django Scoped Access emits system check `scoped_access.W001` if the default cache is process-local.

```python
# settings.py
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://redis:6379/1",
    }
}
```

Token consumption elects exactly one winner under concurrent requests. Redis backends use `GETDEL` (with an atomic Lua fallback for Redis versions before 6.2). Other Django cache backends use `cache.add()` as an atomic consumption claim before deleting the token. Custom cache backends must therefore honor Django's atomic add-if-absent contract.
