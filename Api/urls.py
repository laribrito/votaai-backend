from django.urls import path, include
from rest_framework.routers import DefaultRouter

# ---------------------------------------------------------------------------
# Authentication (Desktop)
# ---------------------------------------------------------------------------
from Api.views.auth.authView import AuthViewSet

# ---------------------------------------------------------------------------
# Desktop Endpoints
# ---------------------------------------------------------------------------
from Api.views.ping.pingDesktopView import PingDesktopView
from Api.views.admin.adminPreRegistrationView import AdminPreRegistrationViewSet
from Api.views.election.electionCreateView import ElectionCreateView
from Api.views.election.availableElectionsView import AvailableElectionsView
from Api.views.election.startElectionView import StartElectionView

# ---------------------------------------------------------------------------
# Router Registration (ViewSets)
# ---------------------------------------------------------------------------
router = DefaultRouter()
router.register(r'admin/pre-registration', AdminPreRegistrationViewSet, basename='admin-pre-registration')

# ---------------------------------------------------------------------------
# URL Patterns
# ---------------------------------------------------------------------------
urlpatterns = [
    # --- Authentication (Desktop) ---
    path('auth/login/', AuthViewSet.as_view({'post': 'login'}), name='auth-login'),

    # --- Testing ---
    path('ping-desktop/', PingDesktopView.as_view(), name='ping-desktop'),

    # --- Eleição (Desktop) ---
    path('election/create/', ElectionCreateView.as_view(), name='election-create'),
    path('election/available/', AvailableElectionsView.as_view(), name='election-available'),
    path('election/start/', StartElectionView.as_view(), name='election-start'),

    # --- ViewSets ---
    path('', include(router.urls)),
]
