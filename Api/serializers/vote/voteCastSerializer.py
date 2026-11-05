from rest_framework import serializers

class VoteCastSerializer(serializers.Serializer):
    """
    Input serializer for casting an encrypted ballot on the mobile device.
    Receives the single-use voting token, the hardware-backed public key of the device,
    the encrypted ballot content (ciphered with the election public key),
    anti-replay nonce, and digital signature from StrongBox hardware.
    """
    token = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The voting token cannot be empty.',
            'required': 'The voting token is required.'
        },
        help_text='Single-use voting token received by the voter.'
    )
    machine_public_key = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The machine public key cannot be empty.',
            'required': 'The machine public key is required.'
        },
        help_text='Hardware-backed public key of the mobile device in PEM or Base64 format.'
    )
    content = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The encrypted vote content cannot be empty.',
            'required': 'The encrypted vote content is required.'
        },
        help_text='Encrypted ballot content (voter choices ciphered with the election public key).'
    )
    nonce = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The nonce cannot be empty.',
            'required': 'The client nonce is required.'
        },
        help_text='Unique client nonce for replay prevention.'
    )
    signature = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Optional digital signature produced by StrongBox hardware over the vote payload.'
    )
    id_voto = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Exposed vote ID for verification and audit tracking.'
    )


class VoteCastResponseSerializer(serializers.Serializer):
    """
    Standardized response structure confirming a deposited ballot.
    Returns the generated vote receipt, election ID, timestamp, and confirmed status.
    """
    receipt = serializers.CharField(
        help_text='Anonymous cryptographic vote receipt (id_generated) confirming ballot deposition.'
    )
    election_id = serializers.IntegerField(
        help_text='Unique identifier of the election.'
    )
    deposited_at = serializers.DateTimeField(
        help_text='Timestamp when the ballot was safely deposited into the electoral ballot box.'
    )
    status = serializers.CharField(
        default='CONFIRMED',
        help_text='Status of the ballot deposition.'
    )
    nonce = serializers.CharField(
        required=False,
        allow_null=True,
        default=None,
        help_text='Echoed client nonce.'
    )
    id_voto = serializers.CharField(
        required=False,
        allow_null=True,
        default=None,
        help_text='Echoed exposed vote ID from the ballot package.'
    )
