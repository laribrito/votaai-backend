from django.db import models
from django.db.models import Count

class GroupQuerySet(models.QuerySet):
    """
    QuerySet personalizado para a gestão dos Cargos/Grupos (django.contrib.auth.models.Group).
    Encapsula otimizações de query e buscas de grupos.
    """

    def withDetails(self):
        """
        Otimiza a busca fazendo prefetch das permissões associadas e anotando a contagem de usuários.
        Evita problemas de N+1 queries na serialização.
        """
        return self.prefetch_related('permissions', 'user_set').annotate(
            userCount=Count('user', distinct=True),
            permissionCount=Count('permissions', distinct=True)
        )

    def defaultListOrder(self):
        """
        Retorna os grupos na ordem padrão (alfabética por nome).
        """
        return self.order_by('name')

    def byName(self, name: str):
        """
        Busca grupo por nome com case-insensitive query.
        """
        return self.filter(name__iexact=name)
