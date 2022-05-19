# from xml.etree.ElementInclude import include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import path, include

...

schema_view = get_schema_view(
   openapi.Info(
      title="authsystem",
      default_version='v1',
      description="Testing",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
   path("docs/", schema_view.with_ui("swagger", cache_timeout=0), name="docs-ui"),
   path("v1/", include(("core.urls", "core")))
]