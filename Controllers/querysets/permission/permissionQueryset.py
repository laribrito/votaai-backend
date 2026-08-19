from django.db import models

class PermissionQuerySet(models.QuerySet):
    """
    QuerySet personalizado para a gestão de Permissões (django.contrib.auth.models.Permission).
    Encapsula buscas de permissões padrão e personalizadas no banco de dados.
    """

    def withContentType(self):
        """
        Otimiza a query carregando o ContentType em JOIN (select_related).
        """
        return self.select_related('content_type')

    def defaultListOrder(self):
        """
        Ordena as permissões por aplicação e por codename.
        """
        return self.order_by('content_type__app_label', 'codename')

    def customOnly(self):
        """
        Retorna apenas permissões do domínio da aplicação (ex: app_label='Domain' ou 'Core').
        """
        return self.filter(content_type__app_label__in=['Domain', 'Core'])

    def byCodenamesOrIds(self, identifiers: list):
        """
        Busca permissões flexivelmente por uma lista de IDs inteiros, ou strings (codenames ou app.codename).
        Exemplos de entrada: [1, 2], ['can_manage_users'], ['Domain.can_manage_users']
        """
        if not identifiers:
            return self.none()

        ids = [int(i) for i in identifiers if isinstance(i, int) or (isinstance(i, str) and i.isdigit())]
        codenames = []
        for i in identifiers:
            if isinstance(i, str) and not i.isdigit():
                # Remove prefixo app_label se existir (ex: 'Domain.can_manage_users' -> 'can_manage_users')
                cleanCodename = i.split('.')[-1]
                codenames.append(cleanCodename)

        query = models.Q()
        if ids:
            query |= models.Q(id__in=ids)
        if codenames:
            query |= models.Q(codename__in=codenames)

        if not query:
            return self.none()

        return self.filter(query)
