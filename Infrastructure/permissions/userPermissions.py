from rest_framework.permissions import BasePermission

from Domain.models import DomainPermissions

class CanManageUsers(BasePermission):
    """
    Permission class for user management endpoints.

    Grants access to:
        - Listing users
        - Inviting users
        - Toggling user active status
        - Admin-level profile updates (including role assignment)

    Granted to: Administrador (superuser) and users with CAN_MANAGE_USERS permission.

    To extend with new permission classes, follow this pattern:
        1. Add a codename to DomainPermissions
        2. Seed it in group_signals.py
        3. Create a new BasePermission subclass here
        4. Import it in this __init__.py
    """
    message = "Access denied. Only users with user management permissions can perform this action."

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.is_superuser or request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_USERS)

class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission: allows access if the requesting user is
    the profile owner, a superuser, or has user management permissions.
    """
    message = "You do not have permission to modify this profile."

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj) -> bool:  # type: ignore[override]
        isAdmin = request.user.is_superuser
        hasManagementPerm = request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_USERS)
        isOwner = obj == request.user
        return isAdmin or hasManagementPerm or isOwner
