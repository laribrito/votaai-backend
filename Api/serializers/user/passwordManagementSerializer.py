from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for authenticated users to change their password.
    Requires the old password for security verification.
    """
    oldPassword = serializers.CharField(
        required=True, 
        write_only=True,
        error_messages={'required': 'Current password is required.'}
    )
    newPassword = serializers.CharField(
        required=True, 
        write_only=True, 
        style={'input_type': 'password'},
        error_messages={'required': 'New password is required.'}
    )
    confirmNewPassword = serializers.CharField(
        required=True, 
        write_only=True, 
        style={'input_type': 'password'},
        error_messages={'required': 'Please confirm your new password.'}
    )

    def validate(self, attrs):
        if attrs['newPassword'] != attrs['confirmNewPassword']:
            raise serializers.ValidationError(
                {"confirmNewPassword": "New passwords do not match."}
            )
        
        # Django password complexity check
        try:
            validate_password(attrs['newPassword'])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"newPassword": list(e.messages)})

        return attrs

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for initiating the password reset flow.
    Only requires the email address.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={'required': 'Email address is required.'}
    )

class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for finalizing the password reset using a token.
    Similar to password setup but specific for recovery flow.
    """
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    
    newPassword = serializers.CharField(
        required=True, 
        write_only=True, 
        style={'input_type': 'password'}
    )
    confirmNewPassword = serializers.CharField(
        required=True, 
        write_only=True, 
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        if attrs['newPassword'] != attrs['confirmNewPassword']:
            raise serializers.ValidationError(
                {"confirmNewPassword": "Passwords do not match."}
            )
            
        try:
            validate_password(attrs['newPassword'])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"newPassword": list(e.messages)})

        return attrs
