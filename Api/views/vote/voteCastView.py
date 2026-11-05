from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

from Api.serializers.vote.voteCastSerializer import (
    VoteCastSerializer,
    VoteCastResponseSerializer
)
from Controllers.actions.vote.voteActions import VoteActions

class VoteCastView(APIView):
    """
    Endpoint para envio da cédula eleitoral preenchida pelo dispositivo Mobile.
    
    A requisição é interceptada pelo SEDecryptMiddleware, que:
    1. Descriptografa o envelope híbrido usando a chave TPM do servidor (VotaAI_SecureKey_2).
    2. Valida autenticidade do token de votação de uso único.
    3. Confirma o vínculo estrito da máquina StrongBox que solicitou a cédula.
    4. Deposita o voto criptografado anonimamente na urna (tabela Vote).
    5. Consome o token e marca que o eleitor votou.
    6. Retorna o comprovante eleitoral (receipt) cifrado com a chave pública do mobile.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Depositar voto / Enviar cédula preenchida (Mobile)",
        description=(
            "Recebe a cédula preenchida e criptografada com a chave pública da eleição, o token de uso único, "
            "a chave pública da máquina gerada em hardware StrongBox e a assinatura digital opcional. "
            "Garante anonimato desvinculando o voto depositado da identidade do eleitor, invalida o token "
            "e emite um recibo anônimo de confirmação."
        ),
        request=VoteCastSerializer,
        responses={
            200: VoteCastResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Votação - Mobile"]
    )
    def post(self, request, *args, **kwargs):
        serializer = VoteCastSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        result = VoteActions.castVote(
            serializer.validated_data,
            raw_data=request.data,
            ip_address=ip_address
        )

        return Response(result, status=status.HTTP_200_OK)
