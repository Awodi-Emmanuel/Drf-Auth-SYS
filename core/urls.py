from django.urls import path
from rest_framework.routers import DefaultRouter
from .api_views import AuthViewset

router = DefaultRouter()

router.register("auth", AuthViewset, basename="auth")
# router.register("profile", ProfileViewset, basename="profile")
