import json
from django.utils import timezone
from django.utils.translation import gettext as _
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema

from Api.permissions import IsElectionAdministrator
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Infrastructure.services.seCryptoService import SECryptoService
from Infrastructure.services.votingTokenService import VotingTokenService

class StartElectionView(APIView):
    """
    Inicia uma eleição após verificar a assinatura digital da máquina e a assinatura da eleição.
    Ao iniciar, gera um token de votação único (single-use) por eleitor e envia por e-mail.
    """
    permission_classes = [IsElectionAdministrator]

    @extend_schema(
        summary="Iniciar uma eleição (Desktop)",
        description="Inicia uma eleição após verificar a assinatura digital da máquina e a assinatura específica da eleição.",
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = payload.get("nonceClient2")
        key_handle = payload.get("keyHandle")
        election_signature = payload.get("election_signature")

        if not election_signature:
            return Response({
                "nonceClient2": nonce_client,
                "error": _("Election signature is missing.")
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # 1. Localiza a eleição
            election = Election.objects.filter(key_handle=key_handle, status=ElectionStatus.CREATED).order_by('-created_at').first()
            if not election:
                raise Election.DoesNotExist()

            # 1.5 Valida que o administrador autenticado e a máquina física correspondem ao criador
            user = request.user
            if election.created_by_id != user.id:
                return Response({
                    "nonceClient2": nonce_client,
                    "error": _("Only the administrator that created this election can start it.")
                }, status=status.HTTP_403_FORBIDDEN)

            machine_key = getattr(request, '_machine_public_key', None) or payload.get('machine_public_key')
            if election.created_by and election.created_by.machine_public_key:
                norm_req_key = SECryptoService.to_pem_public_key(machine_key) if machine_key else ""
                norm_creator_key = SECryptoService.to_pem_public_key(election.created_by.machine_public_key)
                if not norm_req_key or norm_req_key.strip() != norm_creator_key.strip():
                    return Response({
                        "nonceClient2": nonce_client,
                        "error": _("Only the physical machine that created this election can start it.")
                    }, status=status.HTTP_403_FORBIDDEN)

            # 2. Valida a assinatura específica da eleição usando sua chave pública
            payload_to_verify = dict(payload)
            payload_to_verify.pop("election_signature", None)
            payload_to_verify.pop("signature", None)
            payload_to_verify.pop("machine_public_key", None)
            payload_bytes = json.dumps(payload_to_verify, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

            if not SECryptoService.verify_signature(election.public_key, payload_bytes, election_signature):
                return Response({
                    "nonceClient2": nonce_client,
                    "error": _("Invalid election signature. Possible spoofing attempt.")
                }, status=status.HTTP_403_FORBIDDEN)

            # 3. Transição de estado para STARTED
            election.status = ElectionStatus.STARTED
            election.start_datetime = timezone.now()
            election.save()

            # Garante a presença das opções 'Branco' e 'Nulo' em todas as perguntas da eleição
            election.ensure_default_ballot_options()

            # 4. Gera token único e envia link de votação por e-mail para cada eleitor
            emails_sent = 0
            for voter in election.electoral_college.all():
                emails_sent += VotingTokenService.generate_and_dispatch(voter, election)

            total_voters = election.electoral_college.count()

            # 5. Retorno estrito conforme esperado pelo Desktop
            return Response({
                "nonceClient2": nonce_client,
                "hora_registrada": election.start_datetime.isoformat(),
                "emails_enviados": emails_sent,
                "total_colegio": total_voters,
                "titulo": election.title
            }, status=status.HTTP_200_OK)

        except Election.DoesNotExist:
            return Response({
                "nonceClient2": nonce_client,
                "error": _("Election not found.")
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "nonceClient2": nonce_client,
                "error": _("Failed to start election."),
                "details": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
