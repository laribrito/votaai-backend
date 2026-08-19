from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import Group
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

from Api.serializers.group.groupSerializer import (
    GroupListSerializer,
    GroupDetailSerializer,
    GroupCreateUpdateSerializer
)
from Controllers.actions.group.groupActions import GroupActions
from Infrastructure.permissions import CanManageGroups

@extend_schema_view(
    list=extend_schema(
        summary="List System Groups/Roles",
        description="Retrieves all groups along with their assigned permissions and user counts.",
        responses={200: GroupListSerializer(many=True)},
        tags=["Group & Role Management"]
    ),
    retrieve=extend_schema(
        summary="Get Group Details",
        description="Retrieves detailed information of a specific group, including its users.",
        responses={200: GroupDetailSerializer},
        tags=["Group & Role Management"]
    ),
    create=extend_schema(
        summary="Create New Group/Role",
        description="Creates a new Django Group and assigns the specified permissions (by ID or codename).",
        request=GroupCreateUpdateSerializer,
        responses={201: GroupDetailSerializer},
        tags=["Group & Role Management"]
    ),
    update=extend_schema(
        summary="Update Group/Role",
        description="Updates group name and replaces its assigned permissions.",
        request=GroupCreateUpdateSerializer,
        responses={200: GroupDetailSerializer},
        tags=["Group & Role Management"]
    ),
    partial_update=extend_schema(
        summary="Partially Update Group/Role",
        description="Partially updates group name and/or permissions.",
        request=GroupCreateUpdateSerializer,
        responses={200: GroupDetailSerializer},
        tags=["Group & Role Management"]
    ),
    destroy=extend_schema(
        summary="Delete Group/Role",
        description="Deletes a group. Protected system roles (e.g., Administrador) cannot be deleted.",
        responses={204: OpenApiResponse(description="Group deleted successfully.")},
        tags=["Group & Role Management"]
    )
)
class GroupViewSet(viewsets.ModelViewSet):
    """
    API ViewSet para CRUD e gestão completa dos Cargos/Grupos (django.contrib.auth.models.Group).
    Integrado com permissões personalizadas do sistema.
    """
    queryset = Group.objects.none()  # Dummy para o Swagger
    permission_classes = [IsAuthenticated, CanManageGroups]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Group.objects.none()
        return GroupActions.getBaseQueryset()

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return GroupDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return GroupCreateUpdateSerializer
        return GroupListSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        group = GroupActions.createGroup(serializer.validated_data)
        responseSerializer = GroupDetailSerializer(group)
        return Response(responseSerializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        group = self.get_object()

        serializer = self.get_serializer(data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        updatedGroup = GroupActions.updateGroup(group, serializer.validated_data)
        responseSerializer = GroupDetailSerializer(updatedGroup)
        return Response(responseSerializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        group = self.get_object()
        GroupActions.deleteGroup(group)
        return Response(status=status.HTTP_204_NO_CONTENT)
