from rest_framework import serializers


class TallyVotesRequestSerializer(serializers.Serializer):
    """Payload para solicitação de votos cifrados para apuração."""
    keyHandle = serializers.CharField(
        required=False,
        help_text="Identificador único da chave da eleição no hardware/storage"
    )
    key_handle = serializers.CharField(
        required=False,
        help_text="Identificador alternativo da chave da eleição"
    )
    nonceClient = serializers.CharField(
        required=False,
        help_text="Nonce de proteção anti-replay gerado pelo Desktop"
    )


class TallyVotesResponseSerializer(serializers.Serializer):
    """Resposta contendo a lista de votos cifrados para apuração soberana."""
    keyHandle = serializers.CharField(help_text="Handle da eleição")
    titulo = serializers.CharField(help_text="Título da eleição")
    status = serializers.CharField(help_text="Status da eleição (CLOSED ou TALLIED)")
    total_votos = serializers.IntegerField(help_text="Quantidade total de votos registrados na urna")
    votes = serializers.ListField(
        child=serializers.DictField(),
        help_text="Lista de cédulas cifradas { id_generated, content }"
    )
    nonceClient = serializers.CharField(required=False, help_text="Nonce retornado para validação anti-replay")


class TallyElectionRequestSerializer(serializers.Serializer):
    """Payload da primeira apuração soberana enviada pelo Desktop autenticado."""
    keyHandle = serializers.CharField(
        required=False,
        help_text="Identificador único da chave da eleição"
    )
    key_handle = serializers.CharField(
        required=False,
        help_text="Identificador alternativo da chave da eleição"
    )
    tally_hash = serializers.CharField(
        required=True,
        help_text="Hash criptográfico SHA-256 de auditoria da apuração"
    )
    private_key = serializers.CharField(
        required=True,
        help_text="Chave privada da eleição em formato PEM (PKCS#8) para abertura pública da apuração"
    )
    results = serializers.DictField(
        required=False,
        help_text="Sumário de contagem de votos apurados por questão/opção"
    )
    nonceClient = serializers.CharField(
        required=False,
        help_text="Nonce de proteção anti-replay gerado pelo Desktop"
    )


class TallyElectionResponseSerializer(serializers.Serializer):
    """Resposta da primeira apuração confirmando a persistência oficial."""
    keyHandle = serializers.CharField(help_text="Handle da eleição")
    titulo = serializers.CharField(help_text="Título da eleição")
    status = serializers.CharField(help_text="Novo status da eleição (TALLIED)")
    tally_id = serializers.IntegerField(help_text="Identificador do registro de apuração criado")
    tally_hash = serializers.CharField(help_text="Hash criptográfico auditado da apuração")
    tally_datetime = serializers.CharField(help_text="Data e hora em que a apuração foi registrada")
    mensagem = serializers.CharField(help_text="Mensagem informativa de sucesso")
    results = serializers.DictField(required=False, help_text="Resultados apurados ecoados")
    nonceClient = serializers.CharField(required=False, help_text="Nonce retornado para validação anti-replay")
