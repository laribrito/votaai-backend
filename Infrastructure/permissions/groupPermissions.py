from rest_framework.permissions import BasePermission
from Domain.models import DomainPermissions

class CanManageGroups(BasePermission):
    """
    Permission class for group management endpoints.

    Grants access to:
        - Listing groups
        - Creating groups
        - Updating groups and group permissions
        - Deleting groups

    Granted to: Administrador (superuser) and users/groups with CAN_MANAGE_GROUPS or CAN_MANAGE_USERS.
    """
    message = "Access denied. Only users with group management permissions can perform this action."

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        if not request.user or not request.user.is_authenticated:
            return False
        return (
            request.user.is_superuser
            or request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_GROUPS)
            or request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_USERS)
        )

class CanManagePermissions(BasePermission):
    """
    Permission class for custom permission management endpoints.

    Grants access to:
        - Listing available permissions
        - Creating custom permissions
        - Updating/Deleting custom permissions

    Granted to: Administrador (superuser) and users/groups with CAN_MANAGE_PERMISSIONS or CAN_MANAGE_USERS.
    """
    message = "Access denied. Only users with permission management capabilities can perform this action."

    def has_permission(self, request, view) -> bool:  # type: ignore[override]
        if not request.user or not request.user.is_authenticated:
            return False
        return (
            request.user.is_superuser
            or request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_PERMISSIONS)
            or request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_USERS)
        )
