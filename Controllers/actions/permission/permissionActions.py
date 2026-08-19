from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from Domain.models.schemas.moderation.userSchema import User
from django.db import transaction
from rest_framework.exceptions import ValidationError

from Controllers.querysets.permission.permissionQueryset import PermissionQuerySet
from Domain.models import DomainPermissions

class PermissionActions:
    """
    Action/Controller responsável por orquestrar regras de negócio de Permissões (padrão e personalizadas).
    """

    @staticmethod
    def getBaseQueryset():
        """
        Retorna todas as permissões cadastradas no sistema ordenadas e com content_type otimizado.
        """
        return PermissionQuerySet(model=Permission).withContentType().defaultListOrder()

    @staticmethod
    def createCustomPermission(validated_data: dict) -> Permission:
        """
        Cria uma permissão personalizada no banco de dados e associa ao ContentType do domínio.
        """
        codename = validated_data.get('codename', '').strip().lower()
        name = validated_data.get('name', '').strip()
        app_label = validated_data.get('app_label', 'Domain').strip()

        # Encontra o content type adequado. Por padrão usa o model principal do Domínio (User)
        if app_label.lower() == 'domain':
            ct = ContentType.objects.get_for_model(User)
        else:
            ct = ContentType.objects.filter(app_label__iexact=app_label).first()
            if not ct:
                ct = ContentType.objects.get_for_model(User)

        if Permission.objects.filter(codename=codename, content_type=ct).exists():
            raise ValidationError({"codename": f"A permission with codename '{codename}' already exists in app '{ct.app_label}'."})

        with transaction.atomic():
            perm = Permission.objects.create(
                codename=codename,
                name=name,
                content_type=ct
            )
            return perm

    @staticmethod
    def updateCustomPermission(permission: Permission, validated_data: dict) -> Permission:
        """
        Atualiza nome e codename de uma permissão personalizada.
        """
        codename = validated_data.get('codename')
        name = validated_data.get('name')

        with transaction.atomic():
            if codename is not None:
                cleanCodename = codename.strip().lower()
                if Permission.objects.filter(codename=cleanCodename, content_type=permission.content_type).exclude(id=permission.id).exists():
                    raise ValidationError({"codename": f"A permission with codename '{cleanCodename}' already exists."})
                permission.codename = cleanCodename

            if name is not None:
                permission.name = name.strip()

            permission.save()
            return permission

    @staticmethod
    def deleteCustomPermission(permission: Permission) -> None:
        """
        Exclui uma permissão personalizada.
        Impede a exclusão de permissões nativas/crud automáticas do Django ou críticas de sistema.
        """
        if permission.codename.startswith(('add_', 'change_', 'delete_', 'view_')):
            raise ValidationError({"detail": "Cannot delete Django standard built-in model permissions (add/change/delete/view)."})

        protected = [
            DomainPermissions.CAN_MANAGE_USERS,
            DomainPermissions.CAN_MANAGE_GROUPS,
            DomainPermissions.CAN_MANAGE_PERMISSIONS
        ]
        if permission.codename in protected:
            raise ValidationError({"detail": f"The core permission '{permission.codename}' is protected and cannot be deleted."})

        with transaction.atomic():
            permission.delete()
