from django.utils.translation import gettext as _
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError, PermissionDenied
from drf_spectacular.utils import extend_schema

from Api.permissions import IsElectionAdministrator
from Domain.models.schemas.election.electionSchema import Election
from Controllers.actions.election.electionActions import ElectionActions
from Api.serializers.election.tallyElectionSerializer import (
    TallyVotesRequestSerializer,
    TallyVotesResponseSerializer,
    TallyElectionRequestSerializer,
    TallyElectionResponseSerializer,
)


class TallyElectionVotesView(APIView):
    """
    Retorna a lista de cédulas cifradas de uma eleição encerrada (CLOSED) ou apurada (TALLIED).
    Enquanto a eleição estiver apenas encerrada (CLOSED), apenas o Desktop autenticado criador
    pode requisitar os votos para realizar a primeira apuração soberana.
    """
    permission_classes = [IsElectionAdministrator]

    @extend_schema(
        summary="Obter votos cifrados para apuração (Desktop)",
        description=(
            "Retorna todas as cédulas cifradas da urna para a realização da contagem soberana dos votos. "
            "A requisição deve ser enviada dentro do envelope criptográfico do TPM."
        ),
        request=TallyVotesRequestSerializer,
        responses={
            200: TallyVotesResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}, "details": {"type": "object"}}},
            403: {"type": "object", "properties": {"error": {"type": "string"}}},
            404: {"type": "object", "properties": {"error": {"type": "string"}}},
        },
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = (
            payload.get("nonceClient")
            or payload.get("nonceClient3")
            or payload.get("nonceClient2")
            or payload.get("nonce")
        )

        try:
            machine_public_key = getattr(request, '_machine_public_key', None) or payload.get('machine_public_key')
            user = request.user if (request.user and request.user.is_authenticated) else None

            result = ElectionActions.obterVotosEleicao(
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
                "error": _("Failed to retrieve election votes."),
                "details": detail
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            err_data = {
                "error": _("An unexpected error occurred while retrieving election votes."),
                "details": str(e)
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)


class TallyElectionView(APIView):
    """
    Registra a primeira apuração oficial e salva a chave privada da eleição.
    Exige autenticação estrita da estação desktop criadora.
    """
    permission_classes = [IsElectionAdministrator]

    @extend_schema(
        summary="Salvar primeira apuração e registrar chave privada (Desktop)",
        description=(
            "Recebe o hash de auditoria da primeira apuração soberana e a chave privada da eleição (PEM). "
            "Valida que a chave privada deriva a chave pública da eleição, cria o registro oficial de Tally, "
            "persiste a chave privada no banco e atualiza o status do pleito para TALLIED, viabilizando "
            "a verificação independente e apuração por qualquer pessoa."
        ),
        request=TallyElectionRequestSerializer,
        responses={
            200: TallyElectionResponseSerializer,
            400: {"type": "object", "properties": {"error": {"type": "string"}, "details": {"type": "object"}}},
            403: {"type": "object", "properties": {"error": {"type": "string"}}},
            404: {"type": "object", "properties": {"error": {"type": "string"}}},
        },
        tags=["Eleições - Desktop"]
    )
    def post(self, request, *args, **kwargs):
        payload = request.data if isinstance(request.data, dict) else {}
        nonce_client = (
            payload.get("nonceClient")
            or payload.get("nonceClient3")
            or payload.get("nonceClient2")
            or payload.get("nonce")
        )

        try:
            machine_public_key = getattr(request, '_machine_public_key', None) or payload.get('machine_public_key')
            user = request.user if (request.user and request.user.is_authenticated) else None

            result = ElectionActions.apurarEleicao(
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
                "error": _("Failed to save election tally."),
                "details": detail
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            err_data = {
                "error": _("An unexpected error occurred while saving election tally."),
                "details": str(e)
            }
            if nonce_client:
                err_data["nonceClient"] = nonce_client
            return Response(err_data, status=status.HTTP_400_BAD_REQUEST)
