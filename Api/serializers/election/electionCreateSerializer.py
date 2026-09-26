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

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)

        # English aliases only (camelCase / snake_case)
        if 'electoralCollege' in mutable_data and 'electoral_college' not in mutable_data:
            mutable_data['electoral_college'] = mutable_data['electoralCollege']

        if 'publicKey' in mutable_data and 'public_key' not in mutable_data:
            mutable_data['public_key'] = mutable_data['publicKey']

        if 'keyHandle' in mutable_data and 'key_handle' not in mutable_data:
            mutable_data['key_handle'] = mutable_data['keyHandle']

        if 'startDatetime' in mutable_data and 'start_datetime' not in mutable_data:
            mutable_data['start_datetime'] = mutable_data['startDatetime']
        elif 'startDate' in mutable_data and 'start_datetime' not in mutable_data:
            mutable_data['start_datetime'] = mutable_data['startDate']
        elif 'start_date' in mutable_data and 'start_datetime' not in mutable_data:
            mutable_data['start_datetime'] = mutable_data['start_date']

        if 'endDatetime' in mutable_data and 'end_datetime' not in mutable_data:
            mutable_data['end_datetime'] = mutable_data['endDatetime']
        elif 'endDate' in mutable_data and 'end_datetime' not in mutable_data:
            mutable_data['end_datetime'] = mutable_data['endDate']
        elif 'end_date' in mutable_data and 'end_datetime' not in mutable_data:
            mutable_data['end_datetime'] = mutable_data['end_date']

        if 'machinePublicKey' in mutable_data and 'machine_public_key' not in mutable_data:
            mutable_data['machine_public_key'] = mutable_data['machinePublicKey']
        elif 'client_public_key' in mutable_data and 'machine_public_key' not in mutable_data:
            mutable_data['machine_public_key'] = mutable_data['client_public_key']

        return super().to_internal_value(mutable_data)


class ElectionCreateResponseSerializer(serializers.Serializer):
    """
    Response serializer for election creation.
    Returns election id, count of questions and options, and server digital signature.
    """
    id = serializers.IntegerField(help_text='Unique identifier of the created election')
    questions_count = serializers.IntegerField(help_text='Total count of questions in the ballot')
    options_count = serializers.IntegerField(help_text='Total count of voting options across all questions')
    signature = serializers.CharField(help_text='Server digital signature generated with TPM hardware key (VotaAI_SecureKey_1)')
