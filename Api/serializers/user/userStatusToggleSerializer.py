from rest_framework import serializers

class UserStatusToggleResponseSerializer(serializers.Serializer):
    """
    Serializer for the successful status toggle response.
    """
    message = serializers.CharField(help_text="Human-readable success message.")
    username = serializers.CharField(help_text="Username of the affected user.")
    statusLabel = serializers.CharField(help_text="The new status: Active or Inactive.")

class UserStatusToggleErrorResponseSerializer(serializers.Serializer):
    """
    Specific error response serializer for status toggle operations.
    Renamed to avoid schema collisions in Swagger documentation.
    """
    detail = serializers.CharField(help_text="Detailed description of the error.")
    