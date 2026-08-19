from rest_framework import serializers
from Domain.models.schemas.moderation.userSchema import User
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

class UserListSerializer(serializers.ModelSerializer):
    """
    Serializer optimized for the User List table.
    Returns UI-specific fields including the full list of assigned roles.
    """
    fullName = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField() # Changed from 'role' to 'roles'
    permissions = serializers.SerializerMethodField()
    statusControl = serializers.SerializerMethodField() # Changed from status_label to statusControl

    class Meta:
        model = User
        fields = [
            'id',
            'first_name',
            'last_name',
            'fullName',
            'username',
            'email',
            'roles', # Updated field name
            'permissions',
            'statusControl'
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_fullName(self, obj) -> str:
        """
        Concatenates first and last name. Falls back to username if empty.
        """
        fullName = f"{obj.first_name} {obj.last_name}".strip()
        return fullName if fullName else obj.username

    @extend_schema_field(OpenApiTypes.OBJECT) # Typed as Object/Array in Swagger
    def get_roles(self, obj) -> list[dict[str, str]]:
        """
        Retrieves all group names associated with the user.
        Returns a list of objects (e.g., [{"name": "Administrador"}]).
        """
        # [Integração Backend -> Frontend]
        # Mantemos `roles` como array de objetos `{ name }` para alinhar com
        # os componentes de tabela/formulário e o contrato tipado do frontend.
        # Uses the prefetched 'groups' to avoid N+1 queries
        return [{"name": role_name} for role_name in obj.groups.values_list('name', flat=True)]

    @extend_schema_field({'type': 'array', 'items': {'type': 'string'}})
    def get_permissions(self, obj) -> list[str]:
        """
        Returns all effective permission codenames for the user.
        Includes permissions inherited from groups and directly assigned ones.
        Superusers receive all available codenames.
        """
        # get_all_permissions() returns strings like 'Domain.can_manage_users'
        # We strip the app label prefix, returning only the codename (e.g. 'can_manage_users')
        allPerms = obj.get_all_permissions()
        return sorted([perm.split('.')[-1] for perm in allPerms])

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_statusControl(self, obj) -> dict:
        """
        Provides a structured status control object tailored for the Frontend Dumb View.
        """
        return {
            "name": "Ativo" if obj.is_active else "Inativo",
            "badge_color": "75dc60" if obj.is_active else "fc6464",
            "allow_editing": True
        }
    