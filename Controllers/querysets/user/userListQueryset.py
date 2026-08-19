from django.db import models
from django.db.models import Q

class UserListQuerySet(models.QuerySet):
    """
    QuerySet focado na listagem de usuários.
    Encapsula lógica de busca e otimizações de banco.
    """

    def withRoles(self):
        """
        Otimiza a query buscando os grupos (roles) via prefetch_related para evitar N+1.
        """
        return self.prefetch_related('groups')

    def searchByTerm(self, value):
        """
        Filtra usuários por termos gerais (nome, email, username).
        """
        return self.filter(
            Q(username__icontains=value) |
            Q(email__icontains=value) |
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value)
        )

    def defaultListOrder(self):
        """
        Ordem padrão da listagem: os mais recentes primeiro.
        """
        return self.order_by('-date_joined')

    def countActive(self):
        """Conta usuários ativos."""
        return self.filter(is_active=True).count()

    def countInactive(self):
        """Conta usuários inativos."""
        return self.filter(is_active=False).count()

    def countByRole(self, role_name):
        """Conta usuários por cargo (evitando duplicidade)."""
        return self.filter(groups__name=role_name).distinct().count()
    