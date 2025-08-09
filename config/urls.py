from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),

    # clear top-level namespaces
    path("api/auth/", include("accounts.auth_urls")),
    path("api/profiles/", include("accounts.profile_urls")),
    path("api/", include("accounts.moderation_urls")),   # gives /api/blocks/ and /api/reports/
    path("api/", include("accounts.messaging_urls")),    # gives /api/conversations/...
    
    # docs
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)