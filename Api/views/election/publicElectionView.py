from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from django.db.models import Count, Q

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Controllers.actions.election.electionActions import ElectionActions
from Api.serializers.election.publicElectionSerializer import (
    PublicElectionListSerializer,
    PublicElectionDetailSerializer,
)


@extend_schema_view(
    list=extend_schema(
        summary="Listar eleições para acompanhamento (Público)",
        description="Retorna a lista de todas as eleições públicas a partir do status de iniciada (STARTED, CLOSED, TALLIED) para acompanhamento público, contendo dados essenciais, datas de início e finalização e métricas de quórum.",
        tags=["Eleições - Público"],
        parameters=[
            OpenApiParameter(
                name="search",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filtrar eleições por título (busca textual)."
            ),
            OpenApiParameter(
                name="title",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filtrar eleições por título."
            ),
        ],
        responses={200: PublicElectionListSerializer(many=True)},
        auth=[]
    ),
    retrieve=extend_schema(
        summary="Acompanhar eleição e quórum via retrieve (Público)",
        description="Retorna os dados públicos de acompanhamento de uma eleição específica, incluindo o colegiado eleitoral e a indicação de quem já votou para monitoramento do quórum.",
        tags=["Eleições - Público"],
        parameters=[
            OpenApiParameter(
                name="has_voted",
                type=OpenApiTypes.BOOL,
                location=OpenApiParameter.QUERY,
                description="Filtrar membros do colegiado eleitoral por status de voto (true para quem já votou, false para pendentes)."
            ),
            OpenApiParameter(
                name="search",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Filtrar membros do colegiado eleitoral por nome, apelido ou e-mail."
            ),
        ],
        responses={
            200: PublicElectionDetailSerializer,
            404: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        auth=[]
    )
)
class PublicElectionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet pública para consulta e acompanhamento de eleições pelo público em geral.
    - list: Listagem de todas as eleições a partir do status de iniciada (STARTED, CLOSED, TALLIED).
    - retrieve: Acompanhamento de uma eleição via retrieve, retornando colegiado eleitoral e quem votou.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    pagination_class = None

    def get_queryset(self):
        if self.action == 'list':
            search_term = self.request.query_params.get('search') or self.request.query_params.get('title')
            return ElectionActions.buscarEleicoesAbertas(search_term=search_term)

        # Para retrieve, apenas eleições iniciadas ou concluídas (CREATED são rascunhos ainda não publicados)
        return Election.objects.exclude(status=ElectionStatus.CREATED).annotate(
            total_voters=Count('electoral_college', distinct=True),
            voted_count=Count('electoral_college', filter=Q(electoral_college__has_voted=True), distinct=True)
        ).prefetch_related('electoral_college')

    def get_serializer_class(self):
        if self.action == 'list':
            return PublicElectionListSerializer
        return PublicElectionDetailSerializer
