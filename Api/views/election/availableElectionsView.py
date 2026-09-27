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
                client_key = getattr(request, '_client_public_key', None) or decrypted_payload.get("machine_public_key")
                if not client_key:
                    pub_key_path = Path(getattr(settings, 'BASE_DIR', Path.cwd())) / 'desktop_public_key.txt'
                    if pub_key_path.exists():
                        with open(pub_key_path, 'r', encoding='utf-8') as f:
                            client_key = f.read().strip()
                if client_key:
                    user = User.objects.filter(machine_public_key=str(client_key).strip()).first()

            if not user:
                try:
                    loaded_key = SECryptoService.get_client_public_key('desktop')
                    if loaded_key:
                        if hasattr(loaded_key, 'public_bytes'):
                            pem_str = loaded_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            ).decode('utf-8').strip()
                            user = User.objects.filter(machine_public_key=pem_str).first()
                        elif isinstance(loaded_key, str):
                            user = User.objects.filter(machine_public_key=loaded_key.strip()).first()
                except Exception:
                    pass

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
