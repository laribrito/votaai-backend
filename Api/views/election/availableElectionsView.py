from pathlib import Path
from django.conf import settings
from django.utils.translation import gettext as _
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema

from Api.permissions import IsElectionAdministrator
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.seCryptoService import SECryptoService
from cryptography.hazmat.primitives import serialization

class AvailableElectionsView(APIView):
    """
    Retorna as eleições com status CREATED prontas para serem iniciadas pela máquina física.
    """
    permission_classes = [IsElectionAdministrator]

    @extend_schema(
        summary="Listar eleições disponíveis para iniciar (Desktop)",
        description="Retorna as eleições com status CREATED prontas para serem iniciadas pela máquina física.",
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        decrypted_payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = decrypted_payload.get("nonceClient1")

        try:
            # 1. Identifica o administrador autenticado e valida o vínculo com a máquina física
            user = request.user
            machine_key = getattr(request, '_machine_public_key', None) or decrypted_payload.get('machine_public_key')
            if not machine_key:
                return Response({
                    "nonceClient1": nonce_client,
                    "error": _("Machine public key is required.")
                }, status=status.HTTP_400_BAD_REQUEST)

            if user.machine_public_key:
                norm_req_key = SECryptoService.to_pem_public_key(machine_key)
                norm_user_key = SECryptoService.to_pem_public_key(user.machine_public_key)
                if norm_req_key.strip() != norm_user_key.strip():
                    return Response({
                        "nonceClient1": nonce_client,
                        "error": _("This physical machine is not linked to the authenticated administrator.")
                    }, status=status.HTTP_403_FORBIDDEN)

            # 2. Busca eleições daquela máquina/pessoa (status configurável, default CREATED)
            target_status = decrypted_payload.get("status") or ElectionStatus.CREATED
            filter_kwargs = {
                "status": target_status,
                "created_by": user
            }
            if target_status == ElectionStatus.CREATED:
                filter_kwargs["start_datetime__isnull"] = True

            available_elections = Election.objects.filter(**filter_kwargs).order_by('-created_at')

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
