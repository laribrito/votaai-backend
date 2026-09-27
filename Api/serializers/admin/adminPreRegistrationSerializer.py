from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

class AdminPreRegistrationStartSerializer(serializers.Serializer):
    """
    Input serializer for initiating administrator user pre-registration.
    Receives email, password, machine public key and machine user identifier.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': _('Email is required.')}
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={'required': _('Password is required.')}
    )
    machine_public_key = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Machine RSA public key in PEM format. Can be sent in body or extracted by middleware.'
    )
    machine_user = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        max_length=64,
        help_text='Unique, OS-agnostic identifier of the physical device/machine (e.g. dev-xxxxxxxx).'
    )

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)

        # Chave pública (aliases em inglês)
        for alias in ['client_public_key', 'machinePublicKey']:
            if alias in mutable_data and 'machine_public_key' not in mutable_data:
                mutable_data['machine_public_key'] = mutable_data[alias]
                break

        # Fallback para chave pública do request (armazenada pelo middleware)
        if not mutable_data.get('machine_public_key'):
            request = self.context.get('request')
            if request and getattr(request, '_client_public_key', None):
                mutable_data['machine_public_key'] = request._client_public_key

        # Identificador da máquina (aliases em inglês)
        for alias in ['device_id', 'deviceId', 'machine_id', 'machineId', 'machineUser']:
            if alias in mutable_data and 'machine_user' not in mutable_data:
                mutable_data['machine_user'] = mutable_data[alias]
                break

        return super().to_internal_value(mutable_data)


class AdminPreRegistrationConfirmSerializer(serializers.Serializer):
    """
    Input serializer for confirming administrator user pre-registration via TOTP and machine signature.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': _('Email is required.')}
    )
    totp_code = serializers.CharField(
        required=True,
        max_length=10,
        error_messages={'required': _('TOTP code is required.')}
    )
    signature = serializers.CharField(
        required=True,
        error_messages={'required': _('Machine digital signature is required.')}
    )


class AdminPreRegistrationStartResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for step 1.
    """
    message = serializers.CharField()
    provisioning_uri = serializers.CharField()
    signature = serializers.CharField()


class AdminPreRegistrationConfirmResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for step 2.
    """
    message = serializers.CharField()
    signature = serializers.CharField()

