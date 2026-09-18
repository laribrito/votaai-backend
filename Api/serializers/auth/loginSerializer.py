from rest_framework import serializers
from Domain.models.schemas.moderation.userSchema import User
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

class LoginSerializer(serializers.Serializer):
    """
    Validates the login credentials (username, password, 2FA TOTP code and machine signature)
    received from the client.
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
    codigo_totp = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        help_text="Código numérico de 6 dígitos gerado pelo aplicativo autenticador (TOTP)."
    )
    assinatura = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        help_text="Assinatura digital RSA da máquina gerada via hardware TPM."
    )
    usuario_maquina = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        help_text="Identificador único da máquina física."
    )

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'codigoTotp' in mutable_data and 'codigo_totp' not in mutable_data:
            mutable_data['codigo_totp'] = mutable_data['codigoTotp']
        if 'totp_code' in mutable_data and 'codigo_totp' not in mutable_data:
            mutable_data['codigo_totp'] = mutable_data['totp_code']
        if 'machine_user' in mutable_data and 'usuario_maquina' not in mutable_data:
            mutable_data['usuario_maquina'] = mutable_data['machine_user']
        if 'device_id' in mutable_data and 'usuario_maquina' not in mutable_data:
            mutable_data['usuario_maquina'] = mutable_data['device_id']
        return super().to_internal_value(mutable_data)

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
