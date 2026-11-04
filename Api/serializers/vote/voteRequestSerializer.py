from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes

class VoteRequestSerializer(serializers.Serializer):
    """
    Input serializer for requesting a ballot on the mobile device.
    Receives the single-use voting token, the hardware-backed public key of the device,
    and optional Android KeyStore attestation certificate chain.
    """
    token = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The voting token cannot be empty.',
            'required': 'The voting token is required.'
        },
        help_text='Single-use voting token received by the voter via email or QR Code.'
    )
    machine_public_key = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The machine public key cannot be empty.',
            'required': 'The machine public key is required.'
        },
        help_text='Hardware-backed RSA/EC public key of the mobile device in PEM or Base64 format.'
    )
    attestation_certificates = serializers.ListField(
        child=serializers.CharField(),
        required=True,
        allow_empty=False,
        error_messages={
            'required': 'Android KeyStore hardware attestation certificates (TEE or StrongBox) are required.',
            'empty': 'Android KeyStore hardware attestation certificates cannot be empty.'
        },
        help_text='X.509 certificate chain from Android KeyStore Key Attestation proving hardware backing (TEE or StrongBox).'
    )
    nonce = serializers.CharField(
        required=True,
        error_messages={
            'blank': 'The nonce cannot be empty.',
            'required': 'The client nonce is required.'
        },
        help_text='Unique client nonce for replay prevention and attestation challenge.'
    )
    previous_id_voto = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Optional previous unused vote ID to be invalidated/replaced if the voter re-requests the ballot.'
    )


class OptionItemSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Unique identifier of the voting option')
    label = serializers.CharField(help_text='Display text of the option')


class QuestionItemSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Unique identifier of the ballot question')
    question = serializers.CharField(help_text='Question text')
    order = serializers.IntegerField(help_text='Order on the ballot')
    options = OptionItemSerializer(many=True, help_text='Available options for this question')


class ElectionBallotSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Unique identifier of the election')
    title = serializers.CharField(help_text='Title of the election')
    public_key = serializers.CharField(help_text='Election public key for encrypting the cast ballot')
    start_datetime = serializers.DateTimeField(allow_null=True, help_text='Start time of the election')
    end_datetime = serializers.DateTimeField(allow_null=True, help_text='End time of the election')
    questions = QuestionItemSerializer(many=True, help_text='Ballot questions and voting options')


class VoterProfileSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Voter identifier in the electoral college')
    full_name = serializers.CharField(help_text='Full name of the voter')
    nickname = serializers.CharField(help_text='Voter first name / nickname')
    email = serializers.EmailField(help_text='Email of the voter')


class AttestationInfoSerializer(serializers.Serializer):
    is_hardware_backed = serializers.BooleanField(allow_null=True, help_text='True if verified inside TEE or StrongBox')
    security_level = serializers.CharField(help_text='Security level (e.g. TrustedEnvironment, StrongBox, Software, Unattested)')
    method = serializers.CharField(help_text='Evaluation method (android_key_attestation or public_key_only)')
    verified = serializers.BooleanField(help_text='Whether the key validation passed')
    details = serializers.CharField(required=False, allow_blank=True, help_text='Attestation assessment details')
    warning = serializers.CharField(required=False, allow_blank=True, help_text='Warning message when un-attested')


class VoteRequestResponseSerializer(serializers.Serializer):
    """
    Standardized response structure for a successful vote request.
    Delivers the ballot data (questions and options), the election public key,
    voter profile, attestation evaluation, and the issued anonymous ballot ID ticket.
    """
    election = ElectionBallotSerializer()
    voter = VoterProfileSerializer()
    attestation = AttestationInfoSerializer()
    nonce = serializers.CharField(required=False, allow_null=True, default=None)
    id_voto = serializers.CharField(
        required=False,
        allow_null=True,
        default=None,
        help_text='Randomized ballot ticket identifier generated by the backend for this voting session.'
    )
