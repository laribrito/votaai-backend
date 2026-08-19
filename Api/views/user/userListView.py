from rest_framework import viewsets, mixins
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from Domain.models.schemas.moderation.userSchema import User
from drf_spectacular.utils import extend_schema, OpenApiResponse
# Imports do Projeto
from Api.serializers.user.userListSerializer import UserListSerializer
from Api.filters.user.userListFilter import UserListFilter
from Api.pagination.userListPagination import UserListPagination
from Controllers.actions.user.userListActions import UserListAction
from Infrastructure.permissions import CanManageUsers

@extend_schema(
    summary="List System Users",
    description="Retrieves a list of users. Restricted to **Administrador** and users with management permissions.",
    responses={
        200: UserListSerializer(many=True),
        403: OpenApiResponse(description="Forbidden. Apenas Administradores ou gestores."),
    },
    tags=["User Management"]
)
class UserListViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    View 'burra' que delega a busca de dados para a UserListAction.
    Restrita apenas a Administradores e gestores de usuários.
    """
    queryset = User.objects.none() # Dummy para o Swagger
    
    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, CanManageUsers] # Acesso para Administrador e gestores de usuários

    pagination_class = UserListPagination
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserListFilter

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return User.objects.none()
        
        # Delega a construção do QuerySet para a camada de Action/Controller
        return UserListAction.getBaseQueryset()

    @extend_schema(
        summary="User Statistics",
        description="Retrieves live counts of users separated by status and roles.",
        responses={200: OpenApiResponse(description="Counts object")},
    )
    @action(detail=False, methods=['get'])
    def stats(self, request):
        return Response(UserListAction.get_stats_counts())