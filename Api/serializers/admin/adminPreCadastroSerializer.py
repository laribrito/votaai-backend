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
    machine_public_key = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Machine RSA public key. Can be sent in body or client_public_key envelope.'
    )
    machine_user = serializers.CharField(
        required=True,
        max_length=64,
        error_messages={'required': 'O identificador de usuário da máquina (machine_user/device_id) é obrigatório.'},
        help_text='Unique, OS-agnostic identifier of the physical device/machine (e.g. dev-xxxxxxxx).'
    )


    def to_internal_value(self, data):
        # Suporte a camelCase e aliases comuns
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'password' in mutable_data and 'senha' not in mutable_data:
            mutable_data['senha'] = mutable_data['password']

        # Chave pública (inglês e português)
        for alias in ['chave_publica_maquina', 'chavePublicaMaquina', 'machinePublicKey', 'client_public_key']:
            if alias in mutable_data and 'machine_public_key' not in mutable_data:
                mutable_data['machine_public_key'] = mutable_data[alias]
                break
        if 'machine_public_key' in mutable_data and 'chave_publica_maquina' not in mutable_data:
            mutable_data['chave_publica_maquina'] = mutable_data['machine_public_key']

        # Usuário de máquina (inglês e português)
        for alias in ['usuario_maquina', 'usuarioMaquina', 'machineUser', 'device_id', 'deviceId', 'machine_id', 'machineId']:
            if alias in mutable_data and 'machine_user' not in mutable_data:
                mutable_data['machine_user'] = mutable_data[alias]
                break
        if 'machine_user' in mutable_data and 'usuario_maquina' not in mutable_data:
            mutable_data['usuario_maquina'] = mutable_data['machine_user']

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
