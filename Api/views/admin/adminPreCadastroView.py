from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

from Api.serializers.admin.adminPreCadastroSerializer import (
    AdminPreCadastroIniciarSerializer,
    AdminPreCadastroConfirmarSerializer,
    AdminPreCadastroIniciarResponseSerializer,
    AdminPreCadastroConfirmarResponseSerializer
)
from Controllers.actions.admin.adminPreCadastroActions import AdminPreCadastroActions

class AdminPreCadastroViewSet(viewsets.ViewSet):
    """
    Interface de API para o fluxo criptográfico de pré-cadastro do usuário administrador.
    
    Todas as requisições e respostas passam pelo SEDecryptMiddleware,
    utilizando a chave de hardware do Desktop (VotaAI_SecureKey_1) no TPM.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Iniciar pré-cadastro do usuário admin",
        description=(
            "Recebe email, senha e chave pública da máquina física. "
            "Cria o usuário pendente, vincula a máquina, gera o segredo TOTP e a URI de provisionamento. "
            "Devolve a resposta assinada com o TPM do servidor e cifrada para a chave pública da máquina."
        ),
        request=AdminPreCadastroIniciarSerializer,
        responses={
            200: AdminPreCadastroIniciarResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Admin Pré-Cadastro"],
        auth=[]
    )
    def create(self, request):
        """
        POST /api/admin/pre-cadastro/
        Atalho para iniciar o pré-cadastro.
        """
        return self._iniciar(request)

    @extend_schema(
        summary="Iniciar pré-cadastro do usuário admin (rota explícita)",
        description="Endpoint alternativo idêntico a POST /api/admin/pre-cadastro/.",
        request=AdminPreCadastroIniciarSerializer,
        responses={
            200: AdminPreCadastroIniciarResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Admin Pré-Cadastro"],
        auth=[]
    )
    @action(detail=False, methods=['post'], url_path='iniciar')
    def iniciar(self, request):
        """
        POST /api/admin/pre-cadastro/iniciar/
        """
        return self._iniciar(request)

    def _iniciar(self, request):
        serializer = AdminPreCadastroIniciarSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        client_pub_key_fallback = getattr(request, '_client_public_key', None)
        result = AdminPreCadastroActions.iniciarPreCadastro(
            serializer.validated_data,
            client_pub_key_fallback=client_pub_key_fallback
        )
        return Response(result, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Confirmar pré-cadastro do usuário admin com TOTP",
        description=(
            "Recebe email, codigo_totp e a assinatura digital gerada pela chave privada da máquina. "
            "Valida a assinatura com a chave pública da máquina, valida o código TOTP, ativa o usuário "
            "e atribui a ele o cargo de Administrador."
        ),
        request=AdminPreCadastroConfirmarSerializer,
        responses={
            200: AdminPreCadastroConfirmarResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        tags=["Admin Pré-Cadastro"],
        auth=[]
    )
    @action(detail=False, methods=['post'], url_path='confirmar')
    def confirmar(self, request):
        """
        POST /api/admin/pre-cadastro/confirmar/
        """
        serializer = AdminPreCadastroConfirmarSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = AdminPreCadastroActions.confirmarPreCadastro(serializer.validated_data)
        return Response(result, status=status.HTTP_200_OK)
