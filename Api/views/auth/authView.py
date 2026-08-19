from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from knox.views import LogoutView as KnoxLogoutView, LogoutAllView as KnoxLogoutAllView
from drf_spectacular.utils import extend_schema

# Internal imports
from Api.serializers.auth.loginSerializer import LoginSerializer, LoginResponseSerializer
from Api.serializers.user.userListSerializer import UserListSerializer
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
        resultData = AuthActions.login(inputSerializer.validated_data)

        # 3. Output Formatting (Serialization)
        # We pass the raw objects to the Response Serializer to ensure the JSON matches the contract.
        responseSerializer = LoginResponseSerializer(resultData)

        return Response(responseSerializer.data, status=status.HTTP_200_OK)


@extend_schema(
    summary="Logout (Current Device)",
    description="Invalidates the token used in the Authorization header.",
    request=None,
    responses={204: None},
    auth=['knoxApiToken']
)
class LogoutView(KnoxLogoutView):
    """
    POST /api/auth/logout/
    Wrapper around Knox Logout to add Swagger documentation.
    """
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        super().post(request, format)
        return Response(
            {"detail": "Successfully logged out from this device."},
            status=status.HTTP_200_OK
        )


@extend_schema(
    summary="Logout All Devices",
    description="Invalidates ALL tokens for this user (Security reset).",
    request=None,
    responses={204: None},
    auth=['knoxApiToken']
)
class LogoutAllView(KnoxLogoutAllView):
    """
    POST /api/auth/logoutall/
    Wrapper around Knox LogoutAll to add Swagger documentation.
    """
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        super().post(request, format)
        return Response(
            {"detail": "Successfully logged out from all devices."},
            status=status.HTTP_200_OK
        )


@extend_schema(
    summary="Get Current User",
    description="Returns the profile of the currently authenticated user.",
    responses={200: UserListSerializer},
    auth=['knoxApiToken'],
    tags=["Authentication"]
)
class MeView(APIView):
    """
    GET /api/auth/me/
    Returns the authenticated user's profile data.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserListSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    