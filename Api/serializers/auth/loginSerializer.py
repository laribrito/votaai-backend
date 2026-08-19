from rest_framework import serializers
from Domain.models.schemas.moderation.userSchema import User
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

class LoginSerializer(serializers.Serializer):
    """
    Validates the login credentials (username and password) received from the client.
    Input-only serializer.
    """
    username = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The username field cannot be empty.',
            'required': 'The username field is required.'
        }
    )
    password = serializers.CharField(
        required=True, 
        write_only=True,
        error_messages={
            'blank': 'The password field cannot be empty.',
            'required': 'The password field is required.'
        }
    )

class LoginUserSerializer(serializers.ModelSerializer):
    """
    Schema to format the User object inside the login response.
    Returns 'roles' as a list of objects ({"name": "..."}) to match the frontend auth/user contract.
    """
    roles = serializers.SerializerMethodField()
    fullName = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'fullName', 'roles', 'permissions']

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_roles(self, obj) -> list[dict[str, str]]:
        """
        Retrieves all group names associated with the user.
        """
        # [Integração Backend -> Frontend]
        # Padroniza o payload de `roles` como lista de objetos com chave `name`
        # para manter compatibilidade com o tipo UserAuth usado no frontend.
        return [{"name": role_name} for role_name in obj.groups.values_list('name', flat=True)]

    def get_fullName(self, obj) -> str:
        return f"{obj.first_name} {obj.last_name}".strip()

    @extend_schema_field({'type': 'array', 'items': {'type': 'string'}})
    def get_permissions(self, obj) -> list[str]:
        """
        Returns all effective permission codenames for the user.
        Includes permissions inherited from groups and directly assigned ones.
        """
        allPerms = obj.get_all_permissions()
        return sorted([perm.split('.')[-1] for perm in allPerms])

class LoginResponseSerializer(serializers.Serializer):
    """
    Standardized response structure for a successful login.
    Encapsulates the User data and the Auth Token.
    """
    user = LoginUserSerializer()
    token = serializers.CharField()
    