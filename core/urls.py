from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .api_views import AuthViewSet


router = DefaultRouter()
router.register("auth", AuthViewSet, basename="auth")
# router.register("profile", ProfileViewset, basename="profile")

urlpatterns = [
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

urlpatterns += router.urls