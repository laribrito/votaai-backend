from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from Api.views.election.votingQRCodeView import VotingQRCodeView

urlpatterns = [
    # ==========================================================================
    # Cédula de Votação Web / QR Code (Validação na View via ?token= ou /votar/<token>/)
    # ==========================================================================
    path('votar/', VotingQRCodeView.as_view(), name='voting-qrcode'),
    path('votar/<str:token>/', VotingQRCodeView.as_view(), name='voting-qrcode-token'),

    # ==========================================================================
    # API Routes V1
    # ==========================================================================
    # Connects all routes defined within the Api/ folder.
    # Base prefix is 'api/', resulting in URLs like: /api/auth/login/, etc.
    path('api/', include('Api.urls')),
]

# ==============================================================================
# Django Admin (desativado por padrão em produção: ENABLE_ADMIN=False)
# ==============================================================================
if settings.ENABLE_ADMIN:
    urlpatterns += [
        path('admin/', admin.site.urls),
    ]

# ==============================================================================
# API Documentation - OpenAPI / Swagger (desativada por padrão em produção)
# ==============================================================================
if settings.ENABLE_API_DOCS:
    urlpatterns += [
        # 1. Schema Generation (YAML/JSON)
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),

        # 2. Swagger UI (Interactive Documentation)
        path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

        # 3. Redoc UI (Alternative Clean Interface)
        path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ]