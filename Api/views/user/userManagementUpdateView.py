from rest_framework.generics import UpdateAPIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

# Project Imports
from Infrastructure.permissions import CanManageUsers
from Api.serializers.user.userUpdateSerializer import (
    UserManagementSerializer, 
    UserManagementResponseSerializer, # <--- Uses the With-Role Response
    UserUpdateErrorResponseSerializer
)
from Controllers.actions.user.userUpdateAction import UserUpdateAction
from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet

@extend_schema_view(
    patch=extend_schema(
        summary="Administrador: Atualização parcial do perfil do usuário",
        description="Permite que Administradores atualizem campos específicos (incluindo cargos) de qualquer usuário.",
        request=UserManagementSerializer,
        responses={
            200: OpenApiResponse(response=UserManagementResponseSerializer),
            400: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
            403: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
            404: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
        },
        tags=["User Management"]
    ),
    put=extend_schema(
        summary="Administrador: Atualização completa do perfil do usuário",
        description="Substituição completa dos dados do usuário.",
        request=UserManagementSerializer,
        responses={
            200: OpenApiResponse(response=UserManagementResponseSerializer),
            400: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
            403: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
            404: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
        },
        tags=["User Management"]
    )
)
class UserManagementUpdateView(UpdateAPIView):
    permission_classes = [CanManageUsers]
    serializer_class = UserManagementSerializer

    def get_queryset(self):
        return UserUpdateQuerySet.getBaseQueryset()

    def patch(self, request, *args, **kwargs):
        userInstance = self.get_object()

        # Validation happens in the Api layer
        serializer = UserManagementSerializer(
            userInstance,
            data=request.data,
            partial=True,
            context={'request_user': request.user}
        )
        serializer.is_valid(raise_exception=True)

        # Action receives validated data and returns updated user
        updatedUser = UserUpdateAction.execute(
            userInstance, 
            serializer.validated_data, 
            allowRoleUpdate=True
        )

        # Serialize response in the Api layer
        responseSerializer = UserManagementSerializer(updatedUser)
        return Response({
            "message": "User profile information updated successfully.",
            "user": responseSerializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)