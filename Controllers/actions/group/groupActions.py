from django.contrib.auth.models import Group, Permission
from django.db import transaction
from rest_framework.exceptions import ValidationError

from Controllers.querysets.group.groupQueryset import GroupQuerySet
from Controllers.querysets.permission.permissionQueryset import PermissionQuerySet
from Domain.models import GroupRoles

class GroupActions:
    """
    Action/Controller responsável por orquestrar regras de negócio da gestão de Cargos/Grupos (Groups).
    Separado da camada de API/Serialização para respeitar a arquitetura limpa.
    """

    @staticmethod
    def getBaseQueryset():
        """
        Retorna o QuerySet base otimizado de grupos.
        """
        return GroupQuerySet(model=Group).withDetails().defaultListOrder()

    @staticmethod
    def createGroup(validated_data: dict) -> Group:
        """
        Cria um novo Grupo do Django assinalando as permissões solicitadas.
        """
        name = validated_data.get('name', '').strip()
        permissionIdentifiers = validated_data.get('permissions', [])

        if Group.objects.filter(name__iexact=name).exists():
            raise ValidationError({"name": "A group (role) with this name already exists."})

        with transaction.atomic():
            group = Group.objects.create(name=name)
            if permissionIdentifiers:
                perms = PermissionQuerySet(model=Permission).byCodenamesOrIds(permissionIdentifiers)
                group.permissions.set(perms)
            return group

    @staticmethod
    def updateGroup(group: Group, validated_data: dict) -> Group:
        """
        Atualiza o nome e/ou permissões do Grupo.
        """
        name = validated_data.get('name')
        permissionIdentifiers = validated_data.get('permissions', None)

        with transaction.atomic():
            if name is not None:
                cleanName = name.strip()
                if Group.objects.filter(name__iexact=cleanName).exclude(id=group.id).exists():
                    raise ValidationError({"name": "A group (role) with this name already exists."})
                group.name = cleanName
                group.save()

            if permissionIdentifiers is not None:
                perms = PermissionQuerySet(model=Permission).byCodenamesOrIds(permissionIdentifiers)
                group.permissions.set(perms)

            return group

    @staticmethod
    def deleteGroup(group: Group) -> None:
        """
        Exclui um grupo garantindo a integridade do sistema de permissões.
        Impede a exclusão de grupos críticos de sistema.
        """
        protectedRoles = [GroupRoles.ADMIN.value]
        if group.name in protectedRoles:
            raise ValidationError({"detail": f"The system role '{group.name}' is protected and cannot be deleted."})

        with transaction.atomic():
            group.delete()
