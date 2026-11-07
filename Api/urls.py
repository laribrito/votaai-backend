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
# Mobile Endpoints (Votação)
# ---------------------------------------------------------------------------
from Api.views.vote.voteRequestView import VoteRequestView
from Api.views.vote.voteCastView import VoteCastView

# ---------------------------------------------------------------------------
# Public Endpoints (Acompanhamento e Listagem Aberta)
# ---------------------------------------------------------------------------
from Api.views.election.publicElectionView import PublicElectionViewSet

# ---------------------------------------------------------------------------
# Router Registration (ViewSets)
# ---------------------------------------------------------------------------
router = DefaultRouter()
router.register(r'admin/pre-registration', AdminPreRegistrationViewSet, basename='admin-pre-registration')
router.register(r'public/elections', PublicElectionViewSet, basename='public-election')

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

    # --- Eleição (Público - Acompanhamento e Busca Aberta) ---
    path('election/public/open/', PublicElectionViewSet.as_view({'get': 'list'}), name='election-public-open'),
    path('election/public/<int:pk>/', PublicElectionViewSet.as_view({'get': 'retrieve'}), name='election-public-retrieve'),
    path('election/track/<int:pk>/', PublicElectionViewSet.as_view({'get': 'retrieve'}), name='election-track-retrieve'),

    # --- Votação (Mobile) ---
    path('vote/request/', VoteRequestView.as_view(), name='vote-request'),
    path('vote/cast/', VoteCastView.as_view(), name='vote-cast'),

    # --- ViewSets ---
    path('', include(router.urls)),
]
