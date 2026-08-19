from django.contrib import admin
from django.urls import path, include, re_path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

urlpatterns = [
    # ==========================================================================
    # Django Admin
    # ==========================================================================
    path('admin/', admin.site.urls),

    # ==========================================================================
    # API Routes V1
    # ==========================================================================
    # Connects all routes defined within the Api/ folder.
    # Base prefix is 'api/', resulting in URLs like: /api/auth/login/, etc.
    path('api/', include('Api.urls')),

    # ==========================================================================
    # API Documentation (OpenAPI / Swagger)
    # ==========================================================================
    # 1. Schema Generation (YAML/JSON)
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),

    # 2. Swagger UI (Interactive Documentation)
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    # 3. Redoc UI (Alternative Clean Interface)
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Development only: Serve media files
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# FORÇA O DJANGO A SERVIR MÍDIA EM PRODUÇÃO (Solução de Teste)
urlpatterns += [
    re_path(r'^media/(?P<path>.*)$', serve, {
        'document_root': settings.MEDIA_ROOT,
    }),
]