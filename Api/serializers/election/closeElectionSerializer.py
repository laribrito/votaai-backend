from rest_framework import serializers
from django.utils.translation import gettext_lazy as _


class CloseElectionRequestSerializer(serializers.Serializer):
    msg = serializers.CharField(
        required=False,
        default="CLOSE_ELECTION",
        help_text=_("Mensagem de controle (ex: CLOSE_ELECTION)")
    )
    keyHandle = serializers.CharField(
        required=True,
        help_text=_("Identificador da chave de hardware da eleição no TPM")
    )
    election_signature = serializers.CharField(
        required=True,
        help_text=_("Assinatura digital do payload canônico gerada pela chave privada da eleição")
    )
    nonceClient3 = serializers.CharField(
        required=False,
        help_text=_("Nonce anti-replay da requisição do cliente desktop")
    )
    nonceClient = serializers.CharField(
        required=False,
        help_text=_("Nonce alternativo anti-replay do cliente desktop")
    )
    machine_public_key = serializers.CharField(
        required=False,
        help_text=_("Chave pública da máquina administradora em formato PEM")
    )


class CloseElectionResponseSerializer(serializers.Serializer):
    keyHandle = serializers.CharField(help_text=_("Key handle da eleição"))
    titulo = serializers.CharField(help_text=_("Título da eleição"))
    status = serializers.CharField(help_text=_("Status atualizado (CLOSED)"))
    hora_registrada = serializers.DateTimeField(help_text=_("Data e hora do encerramento (end_datetime)"))
    total_colegio = serializers.IntegerField(help_text=_("Total de eleitores aptos no colégio eleitoral"))
    votos_registrados = serializers.IntegerField(help_text=_("Quantidade de votos depositados na urna"))
    pendentes = serializers.IntegerField(help_text=_("Quantidade de eleitores que não votaram"))
    porcentagem_quorum = serializers.FloatField(help_text=_("Percentual final do quórum de participação"))
    mensagem = serializers.CharField(help_text=_("Mensagem de confirmação"))
    nonceClient3 = serializers.CharField(required=False, help_text=_("Nonce ecoado do cliente"))
    nonceClient = serializers.CharField(required=False, help_text=_("Nonce ecoado do cliente"))
