from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from drf_spectacular.utils import extend_schema, OpenApiResponse

# Project Imports
from Infrastructure.permissions import CanManageUsers
from Api.serializers.user.userStatusToggleSerializer import (
    UserStatusToggleResponseSerializer,
    UserStatusToggleErrorResponseSerializer  # Updated Import
)
from Controllers.actions.user.userToggleStatusActions import UserStatusToggleAction

class UserStatusToggleView(GenericAPIView):
    """
    Dumb View responsible for delegating the user status toggle task to the Action layer.
    Inherits from GenericAPIView to provide metadata for automated Swagger schema generation.
    """
    permission_classes = [IsAuthenticated, CanManageUsers]
    serializer_class = UserStatusToggleResponseSerializer

    @extend_schema(
        summary="Toggle User Active Status",
        description="""
        Reverses the 'is_active' flag for a specific user.
        If the user is deactivated, all Knox sessions are automatically revoked via Domain Observers.

        **Restrictions:**
        - Only Administradores or Gerentes can perform this action.
        - Users cannot deactivate themselves.
        """,
        responses={
            200: UserStatusToggleResponseSerializer,
            401: OpenApiResponse(response=UserStatusToggleErrorResponseSerializer, description="Unauthorized - Token missing or invalid."),
            403: OpenApiResponse(response=UserStatusToggleErrorResponseSerializer, description="Forbidden - Only Administradores allowed or self-deactivation attempt."),
            404: OpenApiResponse(response=UserStatusToggleErrorResponseSerializer, description="User not found."),
        },
        tags=["User Management"]
    )
    def patch(self, request, *args, **kwargs):
        """
        Entry point for the status toggle PATCH request.
        Delegates all logic to UserStatusToggleAction using the 'pk' from URL.
        """
        userId = self.kwargs.get('pk')

        # Proteção: Usuário não pode desativar a si mesmo
        if str(request.user.id) == str(userId):
            raise PermissionDenied("Você não pode desativar sua própria conta.")

        data = UserStatusToggleAction.execute(userId)

        return Response(data, status=status.HTTP_200_OK)
    