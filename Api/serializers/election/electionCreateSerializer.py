from rest_framework import serializers

class ElectionCreateSerializer(serializers.Serializer):
    """
    Serializer para o cadastro de eleições via aplicação Desktop.
    Recebe os dados da cédula, colégio eleitoral, chave pública da eleição,
    keyHandle de hardware, assinatura da máquina física e datas opcionais.
    """
    titulo = serializers.CharField(
        required=True,
        max_length=255,
        error_messages={'required': 'O título da eleição é obrigatório.'}
    )
    cedula = serializers.JSONField(
        required=True,
        error_messages={'required': 'A estrutura da cédula é obrigatória.'}
    )
    colegiadoEleitoral = serializers.JSONField(
        required=True,
        error_messages={'required': 'O colegiado eleitoral é obrigatório.'}
    )
    chavePublica = serializers.CharField(
        required=True,
        error_messages={'required': 'A chave pública da eleição é obrigatória.'}
    )
    keyHandle = serializers.CharField(
        required=True,
        max_length=255,
        error_messages={'required': 'O handle da chave (keyHandle) é obrigatório.'}
    )
    assinatura = serializers.CharField(
        required=True,
        error_messages={'required': 'A assinatura digital da máquina física é obrigatória.'}
    )
    dataHoraInicio = serializers.DateTimeField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Data e hora de início da eleição'
    )
    dataHoraFim = serializers.DateTimeField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Data e hora de término da eleição'
    )
    chave_publica_maquina = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Chave pública RSA da máquina física (opcional se já atrelada ao usuário ou enviada no envelope).'
    )

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)

        # Mapeamento para suportar camelCase e snake_case indistintamente
        if 'colegiado_eleitoral' in mutable_data and 'colegiadoEleitoral' not in mutable_data:
            mutable_data['colegiadoEleitoral'] = mutable_data['colegiado_eleitoral']

        if 'chave_publica' in mutable_data and 'chavePublica' not in mutable_data:
            mutable_data['chavePublica'] = mutable_data['chave_publica']

        if 'key_handle' in mutable_data and 'keyHandle' not in mutable_data:
            mutable_data['keyHandle'] = mutable_data['key_handle']

        if 'signature' in mutable_data and 'assinatura' not in mutable_data:
            mutable_data['assinatura'] = mutable_data['signature']

        if 'data_hora_inicio' in mutable_data and 'dataHoraInicio' not in mutable_data:
            mutable_data['dataHoraInicio'] = mutable_data['data_hora_inicio']

        if 'data_hora_fim' in mutable_data and 'dataHoraFim' not in mutable_data:
            mutable_data['dataHoraFim'] = mutable_data['data_hora_fim']

        if 'chavePublicaMaquina' in mutable_data and 'chave_publica_maquina' not in mutable_data:
            mutable_data['chave_publica_maquina'] = mutable_data['chavePublicaMaquina']

        if 'machine_public_key' in mutable_data and 'chave_publica_maquina' not in mutable_data:
            mutable_data['chave_publica_maquina'] = mutable_data['machine_public_key']

        return super().to_internal_value(mutable_data)


class ElectionCreateResponseSerializer(serializers.Serializer):
    """
    Serializer de resposta da criação da eleição para o Desktop.
    Retorna id da eleição, contagem de perguntas e opções, e assinatura digital do servidor.
    """
    id = serializers.IntegerField(help_text='Identificador único da eleição criada')
    qtdPerguntas = serializers.IntegerField(help_text='Quantidade total de perguntas da cédula')
    qtdOpcoes = serializers.IntegerField(help_text='Quantidade total de opções de voto somando todas as perguntas')
    assinatura = serializers.CharField(help_text='Assinatura digital gerada com o hardware TPM do servidor (VotaAI_SecureKey_1)')
