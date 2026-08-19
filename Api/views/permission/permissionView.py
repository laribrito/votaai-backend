from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import Permission
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

from Api.serializers.permission.permissionSerializer import (
    PermissionSerializer,
    PermissionCreateUpdateSerializer
)
from Controllers.actions.permission.permissionActions import PermissionActions
from Infrastructure.permissions import CanManagePermissions


@extend_schema_view(
    list=extend_schema(
        summary="List Available Permissions",
        description="Retrieves all permissions (Django built-in and custom domain permissions) available for group assignments.",
        responses={200: PermissionSerializer(many=True)},
        tags=["Permission Management"]
    ),
    retrieve=extend_schema(
        summary="Get Permission Details",
        description="Retrieves details of a specific permission.",
        responses={200: PermissionSerializer},
        tags=["Permission Management"]
    ),
    create=extend_schema(
        summary="Create Custom Permission",
        description="Registers a new custom permission dynamically into the system.",
        request=PermissionCreateUpdateSerializer,
        responses={201: PermissionSerializer},
        tags=["Permission Management"]
    ),
    update=extend_schema(
        summary="Update Custom Permission",
        description="Updates the name or codename of a custom permission.",
        request=PermissionCreateUpdateSerializer,
        responses={200: PermissionSerializer},
        tags=["Permission Management"]
    ),
    partial_update=extend_schema(
        summary="Partially Update Custom Permission",
        description="Partially updates the name or codename of a custom permission.",
        request=PermissionCreateUpdateSerializer,
        responses={200: PermissionSerializer},
        tags=["Permission Management"]
    ),
    destroy=extend_schema(
        summary="Delete Custom Permission",
        description="Deletes a custom permission. Protected and built-in model permissions cannot be deleted.",
        responses={204: OpenApiResponse(description="Permission deleted successfully.")},
        tags=["Permission Management"]
    )
)
class PermissionViewSet(viewsets.ModelViewSet):
    """
    API ViewSet para gestão de Permissões (django.contrib.auth.models.Permission).
    Permite listagem total e CRUD de permissões customizadas.
    """
    queryset = Permission.objects.none()  # Dummy para o Swagger
    permission_classes = [IsAuthenticated, CanManagePermissions]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Permission.objects.none()
        return PermissionActions.get_base_queryset()

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return PermissionCreateUpdateSerializer
        return PermissionSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        permission = PermissionActions.create_custom_permission(serializer.validated_data)
        responseSerializer = PermissionSerializer(permission)
        return Response(responseSerializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        permission = self.get_object()

        serializer = self.get_serializer(data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        updatedPermission = PermissionActions.update_custom_permission(permission, serializer.validated_data)
        responseSerializer = PermissionSerializer(updatedPermission)
        return Response(responseSerializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        permission = self.get_object()
        PermissionActions.delete_custom_permission(permission)
        return Response(status=status.HTTP_204_NO_CONTENT)
