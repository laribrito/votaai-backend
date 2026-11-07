from django.utils.translation import gettext as _
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError, PermissionDenied
from drf_spectacular.utils import extend_schema

from Domain.models.schemas.election.electionSchema import Election
from Controllers.actions.election.electionActions import ElectionActions
from Api.serializers.election.closeElectionSerializer import (
    CloseElectionRequestSerializer,
    CloseElectionResponseSerializer,
)


class CloseElectionView(APIView):
    """
    Encerra o período de votação de uma eleição ativa (STARTED), congelando o quórum.
    Exige verificação criptográfica da assinatura da eleição e autenticação da máquina física.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Fechar uma eleição (Desktop)",
        description=(
            "Encerra uma eleição em andamento (STARTED), travando o quórum e impedindo novos votos. "
            "A requisição deve ser enviada pela máquina física autorizada dentro do envelope criptográfico do TPM, "
            "contendo a assinatura digital da eleição (election_signature) gerada com a chave privada de hardware."
        ),
        request=CloseElectionRequestSerializer,
        responses={
            200: CloseElectionResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}, "details": {"type": "object"}}},
            403: {"type": "object", "properties": {"error": {"type": "string"}}},
            404: {"type": "object", "properties": {"error": {"type": "string"}}},
        },
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = (
            payload.get("nonceClient3")
            or payload.get("nonceClient")
            or payload.get("nonceClient2")
            or payload.get("nonce")
        )

        try:
            machine_public_key = getattr(request, '_machine_public_key', None) or payload.get('machine_public_key')
            user = request.user if (request.user and request.user.is_authenticated) else None

            result = ElectionActions.fecharEleicao(
                data=payload,
                user=user,
                machine_public_key=machine_public_key
            )
            return Response(result, status=status.HTTP_200_OK)

        except Election.DoesNotExist:
            err_data = {"error": _("Election not found.")}
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_404_NOT_FOUND)

        except PermissionDenied as pe:
            err_data = {"error": str(pe)}
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_403_FORBIDDEN)

        except ValidationError as ve:
            detail = ve.detail if hasattr(ve, 'detail') else str(ve)
            err_data = {
                "error": _("Failed to close election."),
                "details": detail
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            err_data = {
                "error": _("An unexpected error occurred while closing the election."),
                "details": str(e)
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)
