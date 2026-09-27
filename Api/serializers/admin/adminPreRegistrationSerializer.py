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
        required=True,
        error_messages={'required': _('Machine public key is required.')},
        help_text='Machine RSA public key in PEM format.'
    )
    device_id = serializers.CharField(
        required=True,
        max_length=64,
        error_messages={'required': _('Device ID is required.')},
        help_text='Unique, OS-agnostic identifier of the physical device/machine (e.g. dev-xxxxxxxx).'
    )
    client_public_key = serializers.CharField(
        required=False,
        write_only=True,
        help_text='Sent by desktop as duplicate of machine_public_key.'
    )


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

