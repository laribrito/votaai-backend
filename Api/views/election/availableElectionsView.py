from pathlib import Path
from django.conf import settings
from django.utils.translation import gettext as _
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.seCryptoService import SECryptoService
from cryptography.hazmat.primitives import serialization

class AvailableElectionsView(APIView):
    """
    Retorna as eleições com status CREATED prontas para serem iniciadas pela máquina física.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Listar eleições disponíveis para iniciar (Desktop)",
        description="Retorna as eleições com status CREATED prontas para serem iniciadas pela máquina física.",
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        decrypted_payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = decrypted_payload.get("nonceClient1")

        try:
            # 1. Identifica o usuário vinculado a esta máquina física
            user = request.user if (request.user and request.user.is_authenticated) else None
            if not user:
                client_key = getattr(request, '_client_public_key', None)
                if client_key:
                    user = User.objects.filter(machine_public_key=str(client_key).strip()).first()

            # Retorna vazio se não houver usuário vinculado a esta máquina
            if not user:
                return Response({
                    "nonceClient1": nonce_client,
                    "elections": []
                }, status=status.HTTP_200_OK)

            # 2. Busca eleições criadas e ainda não iniciadas daquela máquina/pessoa
            available_elections = Election.objects.filter(
                status=ElectionStatus.CREATED,
                start_datetime__isnull=True,
                created_by=user
            ).order_by('-created_at')

            elections_data = [
                {
                    "keyHandle": election.key_handle,
                    "titulo": election.title
                } for election in available_elections
            ]

            # 3. Retorno no formato estrito esperado pelo Desktop
            return Response({
                "nonceClient1": nonce_client,
                "elections": elections_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "nonceClient1": nonce_client,
                "error": _("Failed to process available elections request."),
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
