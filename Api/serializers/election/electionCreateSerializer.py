from rest_framework import serializers

class ElectionCreateSerializer(serializers.Serializer):
    """
    Serializer for election registration via Desktop application.
    Receives ballot data, electoral college, election public key,
    hardware keyHandle, physical machine digital signature, and optional dates.
    Accepts only English keys.
    """
    title = serializers.CharField(
        required=True,
        max_length=255,
        error_messages={
            'blank': 'The election title cannot be empty.',
            'required': 'The election title is required.'
        }
    )
    ballot = serializers.JSONField(
        required=True,
        error_messages={
            'required': 'The ballot structure is required.'
        }
    )
    electoral_college = serializers.JSONField(
        required=True,
        error_messages={
            'required': 'The electoral college is required.'
        }
    )
    public_key = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The election public key cannot be empty.',
            'required': 'The election public key is required.'
        }
    )
    key_handle = serializers.CharField(
        required=True,
        max_length=255,
        error_messages={
            'blank': 'The keyHandle cannot be empty.',
            'required': 'The keyHandle is required.'
        }
    )
    signature = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The machine digital signature cannot be empty.',
            'required': 'The machine digital signature is required.'
        }
    )
    start_datetime = serializers.DateTimeField(
        required=False,
        default=None,
        allow_null=True,
        help_text='Start date and time of the election'
    )
    end_datetime = serializers.DateTimeField(
        required=False,
        default=None,
        allow_null=True,
        help_text='End date and time of the election'
    )
    machine_public_key = serializers.CharField(
        required=False,
        default=None,
        allow_null=True,
        help_text='RSA public key of the physical machine.'
    )


class ElectionCreateResponseSerializer(serializers.Serializer):
    """
    Response serializer for election creation.
    Returns election id, count of questions and options, and server digital signature.
    """
    id = serializers.IntegerField(help_text='Unique identifier of the created election')
    questions_count = serializers.IntegerField(help_text='Total count of questions in the ballot')
    options_count = serializers.IntegerField(help_text='Total count of voting options across all questions')
    signature = serializers.CharField(help_text='Server digital signature generated with TPM hardware key (VotaAI_SecureKey_1)')
