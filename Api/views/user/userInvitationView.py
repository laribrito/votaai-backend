from rest_framework import viewsets, status
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

# Internal imports
from Api.serializers.user.userInvitationSerializer import UserInvitationSerializer
from Infrastructure.permissions import CanManageUsers
from Controllers.actions.user.userInvitationActions import UserInvitationActions

class UserInvitationViewSet(viewsets.ViewSet):
    """
    API Interface: User Invitation.

    The 'create' (invite) action is strictly reserved for Administrador users.
    Delegates all business logic to UserInvitationActions.

    NOTE: The old 'setup-password' action has been removed.
    Password setup is now handled by the unified POST /api/password/reset/confirm/.
    """

    permission_classes = [CanManageUsers]
    serializer_class = UserInvitationSerializer

    @extend_schema(
        summary="Invite a new user",
        description=(
            "Creates a pending user and sends an invitation email. "
            "**RESTRICTION:** Only accessible by users in the **Administrador** group or with user management permissions."
        ),
        responses={
            201: {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "example": "User invited successfully. Setup email sent."}
                }
            }
        },
        auth=[{'knoxApiToken': []}],  # type: ignore
        tags=["User Management"]
    )
    def create(self, request):
        """
        POST /api/users/invite/
        Restricted to users in the 'Administrador' group.
        """
        serializer = UserInvitationSerializer(data=request.data, context={'request_user': request.user})
        serializer.is_valid(raise_exception=True)

        # Trigger domain logic via Action layer
        # Original: result = UserInvitationActions.inviteUser(serializer.validated_data)
        # [Integração Backend Real - Propagação de Erro de SMTP]
        # Agora capturamos exceções do envio de e-mail (SMTP) que antes eram engolidas.
        # Se o e-mail falhar, retornamos um erro formatado por campo para que o
        # formulário do frontend exiba a mensagem diretamente no campo de e-mail.
        try:
            result = UserInvitationActions.inviteUser(serializer.validated_data, acting_user=request.user)
        except Exception as e:
            errorMessage = str(e)
            if 'SMTP' in errorMessage or 'Connection refused' in errorMessage or 'getaddrinfo' in errorMessage:
                return Response(
                    {"email": ["Falha ao enviar o e-mail de convite. Verifique se o endereço é válido ou tente novamente."]},
                    status=status.HTTP_400_BAD_REQUEST
                )
            raise

        return Response(result, status=status.HTTP_201_CREATED)