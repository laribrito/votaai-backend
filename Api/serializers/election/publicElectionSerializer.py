from rest_framework import serializers
from django.db.models import Q
from Domain.models.schemas.election.electionSchema import Election
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege


class PublicElectoralCollegeVoterSerializer(serializers.ModelSerializer):
    """
    Serializador público de eleitor no colegiado eleitoral.
    Retorna apenas os dados necessários para identificação e acompanhamento do quórum:
    id, full_name, nickname, email e se já votou (has_voted).
    Nunca expõe senhas ou credenciais de votação.
    """
    class Meta:
        model = ElectoralCollege
        fields = ['id', 'full_name', 'nickname', 'email', 'has_voted']
        read_only_fields = fields


class PublicElectionListSerializer(serializers.ModelSerializer):
    """
    Serializador para busca e listagem pública de eleições em aberto.
    Retorna apenas os metadados necessários e resumo do quórum.
    """
    total_voters = serializers.SerializerMethodField(help_text="Total de eleitores aptos no colegiado eleitoral")
    voted_count = serializers.SerializerMethodField(help_text="Quantidade de votos já registrados")
    quorum_percentage = serializers.SerializerMethodField(help_text="Percentual atual de quórum atingido")

    class Meta:
        model = Election
        fields = [
            'id',
            'title',
            'status',
            'start_datetime',
            'total_voters',
            'voted_count',
            'quorum_percentage',
        ]
        read_only_fields = fields

    def get_total_voters(self, obj) -> int:
        if hasattr(obj, 'total_voters'):
            return obj.total_voters
        return obj.electoral_college.count()

    def get_voted_count(self, obj) -> int:
        if hasattr(obj, 'voted_count'):
            return obj.voted_count
        return obj.electoral_college.filter(has_voted=True).count()

    def get_quorum_percentage(self, obj) -> float:
        total = self.get_total_voters(obj)
        voted = self.get_voted_count(obj)
        if total > 0:
            return round((voted / total) * 100, 2)
        return 0.0


class PublicElectionDetailSerializer(serializers.ModelSerializer):
    """
    Serializador para acompanhamento público detalhado da eleição via retrieve.
    Retorna resumo do quórum e o colegiado eleitoral com status de quem votou.
    """
    total_voters = serializers.SerializerMethodField(help_text="Total de eleitores aptos no colegiado eleitoral")
    voted_count = serializers.SerializerMethodField(help_text="Quantidade de votos já registrados")
    pending_count = serializers.SerializerMethodField(help_text="Quantidade de eleitores que ainda não votaram")
    quorum_percentage = serializers.SerializerMethodField(help_text="Percentual atual de quórum atingido")
    electoral_college = serializers.SerializerMethodField(help_text="Lista dos eleitores do colegiado eleitoral e status de voto")

    class Meta:
        model = Election
        fields = [
            'id',
            'title',
            'status',
            'start_datetime',
            'total_voters',
            'voted_count',
            'pending_count',
            'quorum_percentage',
            'electoral_college',
        ]
        read_only_fields = fields

    def get_total_voters(self, obj) -> int:
        if hasattr(obj, 'total_voters'):
            return obj.total_voters
        return obj.electoral_college.count()

    def get_voted_count(self, obj) -> int:
        if hasattr(obj, 'voted_count'):
            return obj.voted_count
        return obj.electoral_college.filter(has_voted=True).count()

    def get_pending_count(self, obj) -> int:
        total = self.get_total_voters(obj)
        voted = self.get_voted_count(obj)
        return max(0, total - voted)

    def get_quorum_percentage(self, obj) -> float:
        total = self.get_total_voters(obj)
        voted = self.get_voted_count(obj)
        if total > 0:
            return round((voted / total) * 100, 2)
        return 0.0

    def get_electoral_college(self, obj):
        request = self.context.get('request')
        voters_qs = obj.electoral_college.all().order_by('full_name')

        if request:
            has_voted_param = request.query_params.get('has_voted')
            if has_voted_param is not None:
                if str(has_voted_param).lower() in ('true', '1'):
                    voters_qs = voters_qs.filter(has_voted=True)
                elif str(has_voted_param).lower() in ('false', '0'):
                    voters_qs = voters_qs.filter(has_voted=False)

            search_param = request.query_params.get('search') or request.query_params.get('voter_search')
            if search_param:
                search_str = search_param.strip()
                voters_qs = voters_qs.filter(
                    Q(full_name__icontains=search_str) |
                    Q(nickname__icontains=search_str) |
                    Q(email__icontains=search_str)
                )

        return PublicElectoralCollegeVoterSerializer(voters_qs, many=True).data
