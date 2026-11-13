from rest_framework import serializers
from django.db.models import Q
from Domain.models.schemas.election.electionSchema import Election
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege


class PublicElectoralCollegeVoterSerializer(serializers.ModelSerializer):
    """
    Serializador público de eleitor no colegiado eleitoral.
    Retorna apenas os dados necessários para identificação e acompanhamento do quórum:
    id, full_name, nickname, email e se já votou (has_voted).
    Para eleições finalizadas (CLOSED ou TALLIED), indica '(Ausente)' no nome de quem não votou.
    Nunca expõe senhas ou credenciais de votação.
    """
    full_name = serializers.SerializerMethodField(
        help_text="Nome do eleitor, exibindo '(Ausente)' caso a eleição tenha sido encerrada e ele não tenha votado"
    )

    class Meta:
        model = ElectoralCollege
        fields = ['id', 'full_name', 'nickname', 'email', 'has_voted']
        read_only_fields = fields

    def get_full_name(self, obj) -> str:
        name = obj.full_name or ""
        election = self.context.get('election') or getattr(obj, 'election', None)
        if not obj.has_voted and election:
            status = getattr(election, 'status', None)
            if status in ('CLOSED', 'TALLIED') and not name.endswith("(Ausente)"):
                return f"{name} (Ausente)".strip()
        return name


class PublicElectionListSerializer(serializers.ModelSerializer):
    """
    Serializador para busca e listagem pública de eleições em aberto ou encerradas.
    Retorna apenas os metadados necessários e resumo do quórum.
    """
    total_voters = serializers.SerializerMethodField(help_text="Total de eleitores aptos no colegiado eleitoral")
    voted_count = serializers.SerializerMethodField(help_text="Quantidade de votos já registrados")
    quorum_percentage = serializers.SerializerMethodField(help_text="Percentual atual de quórum atingido")
    abstention_percentage = serializers.SerializerMethodField(help_text="Percentual de abstenção da eleição")

    class Meta:
        model = Election
        fields = [
            'id',
            'title',
            'status',
            'start_datetime',
            'end_datetime',
            'total_voters',
            'voted_count',
            'quorum_percentage',
            'abstention_percentage',
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

    def get_abstention_percentage(self, obj) -> float:
        total = self.get_total_voters(obj)
        voted = self.get_voted_count(obj)
        if total > 0:
            return round((max(0, total - voted) / total) * 100, 2)
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
    abstention_percentage = serializers.SerializerMethodField(help_text="Percentual de abstenção da eleição")
    electoral_college = serializers.SerializerMethodField(help_text="Lista dos eleitores do colegiado eleitoral e status de voto")
    private_key = serializers.SerializerMethodField(help_text="Chave privada da eleição revelada após a apuração oficial para verificação pública")
    tallies = serializers.SerializerMethodField(help_text="Histórico das apurações registradas")
    votes = serializers.SerializerMethodField(help_text="Cédulas cifradas depositadas na urna anônima")
    tally_results = serializers.SerializerMethodField(help_text="Resultado oficial da apuração com contagem de votos por pergunta e opção")

    class Meta:
        model = Election
        fields = [
            'id',
            'title',
            'status',
            'start_datetime',
            'end_datetime',
            'total_voters',
            'voted_count',
            'pending_count',
            'quorum_percentage',
            'abstention_percentage',
            'electoral_college',
            'private_key',
            'tallies',
            'votes',
            'tally_results',
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

    def get_abstention_percentage(self, obj) -> float:
        total = self.get_total_voters(obj)
        voted = self.get_voted_count(obj)
        if total > 0:
            return round((max(0, total - voted) / total) * 100, 2)
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

        voter_context = dict(self.context)
        voter_context['election'] = obj
        return PublicElectoralCollegeVoterSerializer(voters_qs, many=True, context=voter_context).data

    def get_private_key(self, obj) -> str | None:
        if getattr(obj, 'status', None) == 'TALLIED':
            return getattr(obj, 'private_key', None)
        return None

    def get_tallies(self, obj) -> list:
        if getattr(obj, 'status', None) == 'TALLIED':
            return [
                {
                    "id": t.id,
                    "tally_hash": t.tally_hash,
                    "tally_datetime": t.tally_datetime.isoformat() if hasattr(t.tally_datetime, 'isoformat') else str(t.tally_datetime)
                }
                for t in obj.tallies.all().order_by('-tally_datetime')
            ]
        return []

    def get_votes(self, obj) -> list:
        if getattr(obj, 'status', None) == 'TALLIED':
            return [
                {
                    "id_generated": v.id_generated,
                    "content": v.content
                }
                for v in obj.votes.all().order_by('id')
            ]
        return []

    def get_tally_results(self, obj) -> dict | None:
        if getattr(obj, 'status', None) != 'TALLIED':
            return None
        tally = obj.tallies.order_by('-tally_datetime').first()
        if not tally or not tally.results or not isinstance(tally.results, dict):
            return None

        results_data = tally.results
        total_voters = self.get_total_voters(obj)
        total_ballots = obj.votes.count()
        abstention_count = max(0, total_voters - total_ballots)
        abstention_percentage = round((abstention_count / total_voters) * 100, 2) if total_voters > 0 else 0.0

        # Se já estiver no formato padronizado com lista de questions
        if "questions" in results_data and isinstance(results_data["questions"], list):
            return {
                "tally_hash": tally.tally_hash,
                "tally_datetime": tally.tally_datetime.isoformat() if hasattr(tally.tally_datetime, 'isoformat') else str(tally.tally_datetime),
                "total_ballots": results_data.get("total_votos", total_ballots),
                "total_voters": results_data.get("total_voters", total_voters),
                "abstention_count": results_data.get("abstention_count", abstention_count),
                "abstention_percentage": results_data.get("abstention_percentage", abstention_percentage),
                "questions": results_data["questions"]
            }

        # Constrói o resultado estruturado a partir do dict legado
        questions_payload = []
        for q in obj.questions.all().prefetch_related('options').order_by('order', 'id'):
            opts_payload = []
            q_votes_total = 0
            q_dict = results_data.get(q.question) or results_data.get(str(q.id)) or results_data.get(q.id) or {}

            for opt in q.options.all().order_by('id'):
                v_count = 0
                if isinstance(q_dict, dict):
                    v_count = q_dict.get(opt.label) or q_dict.get(str(opt.id)) or q_dict.get(opt.id) or 0
                opts_payload.append({
                    "id": opt.id,
                    "label": opt.label,
                    "votes": int(v_count)
                })
                q_votes_total += int(v_count)

            for opt_item in opts_payload:
                pct = round((opt_item["votes"] / q_votes_total) * 100, 2) if q_votes_total > 0 else 0.0
                opt_item["percentage"] = pct

            questions_payload.append({
                "id": q.id,
                "question": q.question,
                "total_votes": q_votes_total,
                "options": opts_payload
            })

        return {
            "tally_hash": tally.tally_hash,
            "tally_datetime": tally.tally_datetime.isoformat() if hasattr(tally.tally_datetime, 'isoformat') else str(tally.tally_datetime),
            "total_ballots": total_ballots,
            "total_voters": total_voters,
            "abstention_count": abstention_count,
            "abstention_percentage": abstention_percentage,
            "questions": questions_payload
        }
