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


class AdminPreRegistrationVerifyEmailSerializer(serializers.Serializer):
    """
    Input serializer for verifying administrator email with the 6-digit code and machine signature.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': _('Email is required.')}
    )
    verification_code = serializers.CharField(
        required=True,
        max_length=10,
        error_messages={'required': _('Verification code is required.')}
    )
    signature = serializers.CharField(
        required=True,
        error_messages={'required': _('Machine digital signature is required.')}
    )
    machine_public_key = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={'required': _('Machine public key is required.')},
        help_text='Machine RSA public key in PEM format.'
    )
    device_id = serializers.CharField(
        required=True,
        max_length=64,
        error_messages={'required': _('Device ID is required.')},
        help_text='Unique identifier of the physical device/machine.'
    )


class AdminPreRegistrationResendEmailSerializer(serializers.Serializer):
    """
    Input serializer for resending the administrator email verification code.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': _('Email is required.')}
    )
    signature = serializers.CharField(
        required=True,
        error_messages={'required': _('Machine digital signature is required.')}
    )
    machine_public_key = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={'required': _('Machine public key is required.')},
        help_text='Machine RSA public key in PEM format.'
    )
    device_id = serializers.CharField(
        required=True,
        max_length=64,
        error_messages={'required': _('Device ID is required.')},
        help_text='Unique identifier of the physical device/machine.'
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
    machine_public_key = serializers.CharField(
        required=True,
        write_only=True,
        error_messages={'required': _('Machine public key is required.')},
        help_text='Machine RSA public key in PEM format.'
    )
    device_id = serializers.CharField(
        required=True,
        max_length=64,
        error_messages={'required': _('Device ID is required.')},
        help_text='Unique identifier of the physical device/machine.'
    )


class AdminPreRegistrationStartResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for step 1 (start pre-registration).
    """
    message = serializers.CharField()
    signature = serializers.CharField()


class AdminPreRegistrationVerifyEmailResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for step 2 (verify email).
    """
    message = serializers.CharField()
    provisioning_uri = serializers.CharField()
    signature = serializers.CharField()


class AdminPreRegistrationResendEmailResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for resending verification email.
    """
    message = serializers.CharField()
    signature = serializers.CharField()


class AdminPreRegistrationConfirmResponseSerializer(serializers.Serializer):
    """
    OpenAPI documentation response serializer for step 3 (confirm TOTP).
    """
    message = serializers.CharField()
    signature = serializers.CharField()

