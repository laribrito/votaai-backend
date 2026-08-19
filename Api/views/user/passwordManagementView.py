from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_spectacular.utils import extend_schema, OpenApiExample

# Internal imports
from Api.serializers.user.passwordManagementSerializer import (
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    ChangePasswordSerializer
)
from Controllers.actions.user.passwordManagementActions import PasswordManagementActions

class PasswordManagementViewSet(viewsets.ViewSet):
    """
    API Interface: Password Management.
    """

    @extend_schema(
        summary="Request Password Reset",
        description="Public endpoint. Sends a reset link to the email if it exists.",
        request=PasswordResetRequestSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        auth=[]
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='reset/request')
    def requestReset(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        result = PasswordManagementActions.requestReset(serializer.validated_data['email'])
        return Response(result, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Confirm Password Reset",
        description="Sets new password using the token received via email.",
        request=PasswordResetConfirmSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}},
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        examples=[
            # Apenas exemplos de RESPOSTA de erro, nomes simples e diretos
            OpenApiExample(
                "Invalid Token",
                value={"error": "Invalid or expired token."},
                response_only=True,
                status_codes=[400]
            ),
            OpenApiExample(
                "Passwords Mismatch",
                value={"confirm_new_password": ["Passwords do not match."]},
                response_only=True,
                status_codes=[400]
            ),
        ],
        auth=[]
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='reset/confirm')
    def confirmReset(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = PasswordManagementActions.confirmReset(serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Change Password",
        description="Changes password for the logged-in user.",
        request=ChangePasswordSerializer,
        responses={
            200: {"type": "object", "properties": {"message": {"type": "string"}}},
            400: {"type": "object", "properties": {"error": {"type": "string"}}}
        },
        examples=[
            # Exemplos de RESPOSTA de erro limpos
            OpenApiExample(
                "Wrong Old Password",
                value={"error": "The old password is incorrect."},
                response_only=True,
                status_codes=[400]
            ),
            OpenApiExample(
                "Passwords Mismatch",
                value={"confirm_new_password": ["New passwords do not match."]},
                response_only=True,
                status_codes=[400]
            )
        ],
        auth=[{'knoxApiToken': []}]
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated], url_path='change')
    def changePassword(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = PasswordManagementActions.changePassword(request.user, serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        