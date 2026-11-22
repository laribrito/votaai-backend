from rest_framework.permissions import BasePermission
from Domain.models.groupChoices import GroupRoles


class IsElectionAdministrator(BasePermission):
    """
    Restringe acesso a usuários autenticados e ativos pertencentes ao grupo
    Administrador (ou superusuários).
    """
    message = "Acesso restrito a administradores autenticados da comissão eleitoral."

    def has_permission(self, request, view) -> bool:
        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated or not user.is_active:
            return False
        if user.is_superuser:
            return True
        return user.groups.filter(name=GroupRoles.ADMIN.value).exists()
