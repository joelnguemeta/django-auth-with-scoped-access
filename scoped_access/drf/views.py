"""Standard endpoints: GET /me/access/ (SPEC §10) and POST reauth (SPEC §7).

Wire them in the host's urlconf::

    path("me/access/", MeAccessView.as_view()),
    path("auth/reauth/", ReAuthView.as_view()),
"""

from __future__ import annotations

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import engine
from ..conf import get_config
from ..reauth import ReAuthService


class MeAccessView(APIView):
    """The caller's effective access — the UI's single source of truth.

    Token claims are informative only (SPEC §10); this endpoint is not.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        summary = engine.access_summary(request.user)
        return Response(
            {
                "principal": {
                    "id": str(request.user.pk),
                    "superuser": request.user.is_superuser,
                    "active": request.user.is_active,
                },
                "permissions": summary["permissions"],
                "assignments": [
                    {
                        "role": {
                            "id": str(a["role"].pk),
                            "name": a["role"].name,
                            "system": a["role"].is_system,
                        },
                        "level": a["level"],
                        "scope": (
                            {"id": str(a["scope"].pk), "label": str(a["scope"])}
                            if a["scope"]
                            else None
                        ),
                        "status": a["status"],
                        "valid_until": a["valid_until"],
                        "permissions": a["permissions"],
                    }
                    for a in summary["assignments"]
                ],
            }
        )


class ReAuthView(APIView):
    """Exchange a fresh proof (v1: password) for a single-use step-up token."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        verifier = request.data.get("verifier", "password")
        credentials = {k: v for k, v in request.data.items() if k != "verifier"}
        token = ReAuthService.issue(request.user, verifier=verifier, **credentials)
        if token is None:
            return Response({"detail": "Invalid credentials."}, status=400)
        return Response({"reauth_token": token, "ttl": get_config().reauth["TTL"]})
