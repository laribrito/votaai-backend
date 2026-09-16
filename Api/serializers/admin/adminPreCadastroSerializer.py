from rest_framework import serializers

class AdminPreCadastroIniciarSerializer(serializers.Serializer):
    """
    Serializer de entrada para o início do pré-cadastro do usuário administrador.
    Recebe email, senha e a chave pública de hardware da máquina.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': 'O e-mail é obrigatório.'}
    )
    senha = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={'required': 'A senha é obrigatória.'}
    )
    chave_publica_maquina = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Chave pública RSA da máquina. Pode vir no corpo ou no envelope client_public_key.'
    )

    def to_internal_value(self, data):
        # Suporte a camelCase e aliases comuns
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'password' in mutable_data and 'senha' not in mutable_data:
            mutable_data['senha'] = mutable_data['password']
        if 'machine_public_key' in mutable_data and 'chave_publica_maquina' not in mutable_data:
            mutable_data['chave_publica_maquina'] = mutable_data['machine_public_key']
        if 'chavePublicaMaquina' in mutable_data and 'chave_publica_maquina' not in mutable_data:
            mutable_data['chave_publica_maquina'] = mutable_data['chavePublicaMaquina']
        return super().to_internal_value(mutable_data)


class AdminPreCadastroConfirmarSerializer(serializers.Serializer):
    """
    Serializer de entrada para a confirmação do pré-cadastro do admin via TOTP e assinatura.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': 'O e-mail é obrigatório.'}
    )
    codigo_totp = serializers.CharField(
        required=True,
        max_length=10,
        error_messages={'required': 'O código TOTP é obrigatório.'}
    )
    assinatura = serializers.CharField(
        required=True,
        error_messages={'required': 'A assinatura digital da máquina é obrigatória.'}
    )

    def to_internal_value(self, data):
        # Suporte a camelCase e aliases comuns
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'codigoTotp' in mutable_data and 'codigo_totp' not in mutable_data:
            mutable_data['codigo_totp'] = mutable_data['codigoTotp']
        if 'totp_code' in mutable_data and 'codigo_totp' not in mutable_data:
            mutable_data['codigo_totp'] = mutable_data['totp_code']
        if 'signature' in mutable_data and 'assinatura' not in mutable_data:
            mutable_data['assinatura'] = mutable_data['signature']
        return super().to_internal_value(mutable_data)


class AdminPreCadastroIniciarResponseSerializer(serializers.Serializer):
    """
    Serializer de documentação OpenAPI para resposta da etapa 1.
    """
    mensagem = serializers.CharField()
    uri_provisionamento = serializers.CharField()
    assinatura = serializers.CharField()


class AdminPreCadastroConfirmarResponseSerializer(serializers.Serializer):
    """
    Serializer de documentação OpenAPI para resposta da etapa 2.
    """
    mensagem = serializers.CharField()
    assinatura = serializers.CharField()
