import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

from Api.serializers.vote.voteRequestSerializer import (
    VoteRequestSerializer,
    VoteRequestResponseSerializer
)
from Controllers.actions.vote.voteActions import VoteActions

logger = logging.getLogger(__name__)

class VoteRequestView(APIView):
    """
    Endpoint para solicitação de cédula de votação por aplicativo Mobile.
    
    Fluxo de processamento e segurança:
    1. O SEDecryptMiddleware descriptografa o envelope híbrido usando a chave TPM do servidor (VotaAI_SecureKey_2)
       e guarda temporariamente a machine_public_key em memória no objeto da requisição para cifrar a resposta.
    2. A View valida o schema dos dados (token, machine_public_key, certificados de hardware e nonce).
    3. A Action valida a integridade do token, elegibilidade do eleitor, estado da eleição e anti-replay do nonce.
    4. Avalia a atestação de hardware do Android KeyStore exigindo chave em hardware seguro (TEE ou StrongBox).
    5. Somente após a aprovação de todas as validações, a machine_public_key e o nonce são vinculados ao token no banco de dados.
    6. Retorna a cédula eleitoral cifrada de ponta a ponta com a chave pública do dispositivo móvel.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Solicitar cédula de votação (Mobile)",
        description=(
            "Recebe o token de votação de uso único, a chave pública e os certificados de atestação de hardware. "
            "Valida o token, verifica o estado da eleição, atesta o hardware via Android KeyStore (TEE ou StrongBox obrigatório) "
            "e, apenas se aprovado, vincula a chave ao token e entrega a cédula eleitoral com perguntas e opções "
            "cifrada de ponta a ponta para a chave do dispositivo."
        ),
        request=VoteRequestSerializer,
        responses={
            200: VoteRequestResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Votação - Mobile"]
    )
    def post(self, request, *args, **kwargs):
        serializer = VoteRequestSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"[VOTE_REQUEST_INVALID_PAYLOAD] Erro de validação de campos: {serializer.errors}")
            serializer.is_valid(raise_exception=True)

        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        result = VoteActions.requestVote(
            serializer.validated_data,
            raw_data=request.data,
            ip_address=ip_address
        )

        return Response(result, status=status.HTTP_200_OK)
