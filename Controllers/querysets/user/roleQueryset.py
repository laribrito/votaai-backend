from django.db import models

class RoleQuerySet(models.QuerySet):
    """
    QuerySet personalizado para os Cargos (Groups do Django).
    Encapsula as buscas de papéis no sistema.
    """

    def defaultListOrder(self):
        """
        Retorna os cargos na ordem padrão (alfabética por nome).
        """
        return self.order_by('name')
