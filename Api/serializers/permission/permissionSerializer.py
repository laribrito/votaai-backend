from rest_framework import serializers
from django.contrib.auth.models import Permission
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer para exibição de Permissões (padrão do Django ou customizadas).
    Inclui campos auxiliares para facilitar o frontend e verificações de ACL.
    """
    app_label = serializers.SerializerMethodField()
    fullCodename = serializers.SerializerMethodField()

    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'app_label', 'fullCodename']

    @extend_schema_field(OpenApiTypes.STR)
    def get_app_label(self, obj) -> str:
        return obj.content_type.app_label if obj.content_type else ''

    @extend_schema_field(OpenApiTypes.STR)
    def get_fullCodename(self, obj) -> str:
        app_label = obj.content_type.app_label if obj.content_type else ''
        return f"{app_label}.{obj.codename}" if app_label else obj.codename

class PermissionCreateUpdateSerializer(serializers.Serializer):
    """
    Serializer de entrada para criação ou atualização de permissões customizadas.
    """
    codename = serializers.CharField(max_length=100, required=True, help_text="Ex: can_export_reports")
    name = serializers.CharField(max_length=255, required=True, help_text="Ex: Can export system reports")
    app_label = serializers.CharField(max_length=100, required=False, default='Domain', help_text="Ex: Domain")

    def validateCodename(self, value):
        # Apenas caracteres alfanuméricos, underscores e hyphens
        clean = value.strip().lower()
        if not clean.replace('_', '').replace('-', '').isalnum():
            raise serializers.ValidationError("Codename must contain only letters, numbers, hyphens, or underscores.")
        return clean
