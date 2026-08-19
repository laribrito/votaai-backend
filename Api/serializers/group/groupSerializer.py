from rest_framework import serializers
from django.contrib.auth.models import Group
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

from Api.serializers.permission.permissionSerializer import PermissionSerializer


class GroupListSerializer(serializers.ModelSerializer):
    """
    Serializer otimizado para listagem de Grupos/Cargos.
    Retorna permissões atribuídas e contagem de usuários sem N+1 queries.
    """
    permissions = PermissionSerializer(many=True, read_only=True)
    userCount = serializers.SerializerMethodField()
    permissionCount = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions', 'userCount', 'permissionCount']

    @extend_schema_field(OpenApiTypes.INT)
    def getUserCount(self, obj) -> int:
        if hasattr(obj, 'userCount'):
            return obj.userCount
        return obj.user_set.count()

    @extend_schema_field(OpenApiTypes.INT)
    def getPermissionCount(self, obj) -> int:
        if hasattr(obj, 'permissionCount'):
            return obj.permissionCount
        return obj.permissions.count()


class GroupUserSummarySerializer(serializers.Serializer):
    """
    Resumo de usuário para visualização dentro do detalhe de um Grupo.
    """
    id = serializers.IntegerField()
    username = serializers.CharField()
    fullName = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_name(self, obj) -> str:
        fullName = f"{getattr(obj, 'first_name', '')} {getattr(obj, 'last_name', '')}".strip()
        return fullName if fullName else getattr(obj, 'username', '')


class GroupDetailSerializer(GroupListSerializer):
    """
    Serializer detalhado de um Grupo, incluindo membros atribuídos.
    """
    users = serializers.SerializerMethodField()

    class Meta(GroupListSerializer.Meta):
        fields = GroupListSerializer.Meta.fields + ['users']

    @extend_schema_field(GroupUserSummarySerializer(many=True))
    def getUsers(self, obj):
        usersQs = obj.user_set.all()[:50]  # Limita aos primeiros 50 membros para performance
        return GroupUserSummarySerializer(usersQs, many=True).data


class GroupCreateUpdateSerializer(serializers.Serializer):
    """
    Serializer para criação e atualização de Grupos e suas Permissões.
    Permite passar permissões como IDs inteiros ou Codenames em string.
    """
    name = serializers.CharField(max_length=150, required=True, help_text="Nome do Cargo/Grupo (ex: Redator)")
    permissions = serializers.ListField(
        child=serializers.JSONField(),
        required=False,
        allow_empty=True,
        help_text="Lista de IDs (inteiros) ou codenames (strings) de permissão para vincular ao grupo."
    )
