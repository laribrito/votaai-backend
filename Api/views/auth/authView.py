from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema

# Internal imports
from Api.serializers.auth.loginSerializer import LoginSerializer, LoginResponseSerializer
from Controllers.actions.auth.authActions import AuthActions

class AuthViewSet(viewsets.ViewSet):
    """
    API Interface: User Authentication.
    """
    
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    @extend_schema(
        summary="User Login",
        description="Authenticates a user and returns their profile info along with an API Token.",
        request=LoginSerializer,
        responses={
            200: LoginResponseSerializer, # Automatically generates the correct schema with 'roles' list
            401: None
        },
        auth=[] # Login is public
    )
    def login(self, request):
        """
        POST /api/auth/login/
        """
        # 1. Input Validation
        inputSerializer = LoginSerializer(data=request.data)
        inputSerializer.is_valid(raise_exception=True)

        # 2. Business Logic Execution
        resultData = AuthActions.login(inputSerializer.validated_data, raw_data=request.data)

        # 3. Output Formatting (Serialization)
        # We pass the raw objects to the Response Serializer to ensure the JSON matches the contract.
        responseSerializer = LoginResponseSerializer(resultData)

        return Response(responseSerializer.data, status=status.HTTP_200_OK)

    