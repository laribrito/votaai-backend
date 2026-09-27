from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

from Api.serializers.election.electionCreateSerializer import (
    ElectionCreateSerializer,
    ElectionCreateResponseSerializer
)
from Controllers.actions.election.electionActions import ElectionActions

class ElectionCreateView(APIView):
    """
    Endpoint para cadastro de novas eleições a partir da aplicação Desktop.
    
    A requisição é interceptada pelo SEDecryptMiddleware, que:
    1. Descriptografa o payload utilizando a chave privada do servidor no hardware TPM (VotaAI_SecureKey_1).
    2. Registra a chave pública da máquina física cliente.
    3. Criptografa a resposta com a chave pública da máquina física.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Cadastrar nova eleição (Desktop)",
        description=(
            "Recebe título, cédula (perguntas e opções), colegiadoEleitoral, "
            "chavePublica da eleição, keyHandle e a assinatura digital da máquina física. "
            "Valida a assinatura da máquina, cria a eleição e retorna o ID, quantidade de "
            "perguntas, quantidade de opções e a assinatura digital gerada pelo TPM do servidor."
        ),
        request=ElectionCreateSerializer,
        responses={
            200: ElectionCreateResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        serializer = ElectionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user if getattr(request, 'user', None) and request.user.is_authenticated else None

        result = ElectionActions.criarEleicao(
            serializer.validated_data,
            raw_data=request.data,
            user=user
        )

        return Response(result, status=status.HTTP_200_OK)
