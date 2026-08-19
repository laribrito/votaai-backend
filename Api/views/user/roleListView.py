from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from Infrastructure.permissions import CanManageUsers
from django.contrib.auth.models import Group
from drf_spectacular.utils import extend_schema

from Api.serializers.user.roleListSerializer import RoleListSerializer
from Controllers.querysets.user.roleQueryset import RoleQuerySet

@extend_schema(
    summary="List Available Roles",
    description="Returns selectable roles (Django Groups) for use in invitation forms and user management.",
    responses={200: RoleListSerializer(many=True)},
    tags=["User Management"]
)
class RoleListView(generics.ListAPIView):
    """
    View 'burra' que retorna Cargos selecionáveis (Django Groups).
    Usada pelo frontend para popular dropdowns de cargos (ex: formulário de convite).
    """
    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Group.objects.none()
        return RoleQuerySet(model=Group).default_list_order()
    serializer_class = RoleListSerializer
    permission_classes = [IsAuthenticated, CanManageUsers]
    pagination_class = None  # Cargos são uma lista pequena e finita; sem necessidade de paginação.
