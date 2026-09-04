from django.urls import path, include
from rest_framework.routers import DefaultRouter

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
from Api.views.auth.authView import AuthViewSet, LogoutView, LogoutAllView, MeView

# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------
from Api.views.user.userInvitationView import UserInvitationViewSet
from Api.views.user.passwordManagementView import PasswordManagementViewSet
from Api.views.user.userToggleStatusView import UserStatusToggleView
from Api.views.user.userProfileUpdateView import UserProfileUpdateView
from Api.views.user.userManagementUpdateView import UserManagementUpdateView
from Api.views.user.userListView import UserListViewSet
from Api.views.user.roleListView import RoleListView
from Api.views.group.groupView import GroupViewSet
from Api.views.permission.permissionView import PermissionViewSet
from Api.views.ping.pingDesktopView import PingDesktopView
from Api.views.admin.adminPreCadastroView import AdminPreCadastroViewSet

# ---------------------------------------------------------------------------
# Router Registration (ViewSets)
# ---------------------------------------------------------------------------
router = DefaultRouter()
router.register(r'admin/pre-cadastro', AdminPreCadastroViewSet, basename='admin-pre-cadastro')
router.register(r'users/invite', UserInvitationViewSet, basename='user-invitation')
router.register(r'password', PasswordManagementViewSet, basename='password-management')
router.register(r'users', UserListViewSet, basename='user-list')
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'permissions', PermissionViewSet, basename='permission')

# ---------------------------------------------------------------------------
# URL Patterns
# ---------------------------------------------------------------------------
urlpatterns = [
    # --- Authentication ---
    path('auth/login/', AuthViewSet.as_view({'post': 'login'}), name='auth-login'),
    path('auth/me/', MeView.as_view(), name='auth-me'),
    path('auth/logout/', LogoutView.as_view(), name='auth-logout'),
    path('auth/logoutall/', LogoutAllView.as_view(), name='auth-logout-all'),

    # --- User Management ---
    path('users/me/update/', UserProfileUpdateView.as_view(), name='user-profile-update'),
    path('users/<int:pk>/management-update/', UserManagementUpdateView.as_view(), name='user-management-update'),
    path('users/<int:pk>/toggle-status/', UserStatusToggleView.as_view(), name='user-toggle-status'),
    path('roles/', RoleListView.as_view(), name='role-list'),

    # --- Testing ---
    path('ping-desktop/', PingDesktopView.as_view(), name='ping-desktop'),

    # --- ViewSets ---
    path('', include(router.urls)),

    # ---------------------------------------------------------------------------
    # Add your domain routes below following the same pattern
    # ---------------------------------------------------------------------------
    # Example:
    # from Api.views.mymodule.mymodel_view import MyModelViewSet
    # router.register(r'mymodels', MyModelViewSet, basename='mymodel')
    # path('mymodels/', MyModelListView.as_view(), name='mymodel-list'),
]
