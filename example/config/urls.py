from django.contrib import admin
from django.urls import include, path
from helpdesk.views import TicketViewSet
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from scoped_access.drf.views import MeAccessView, ReAuthView

router = DefaultRouter()
router.register("tickets", TicketViewSet, basename="ticket")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include(router.urls)),
    path("api/me/access/", MeAccessView.as_view()),
    path("api/auth/reauth/", ReAuthView.as_view()),
    path("api/auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
