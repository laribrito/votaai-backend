from rest_framework.generics import UpdateAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

# Project Imports
from Api.serializers.user.userUpdateSerializer import (
    UserUpdateSerializer, 
    UserUpdateResponseSerializer, # <--- Uses the No-Role Response
    UserUpdateErrorResponseSerializer
)
from Controllers.actions.user.userUpdateAction import UserUpdateAction
from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet

@extend_schema_view(
    patch=extend_schema(
        summary="Update My Profile",
        description="Updates the profile of the currently logged-in user.",
        request=UserUpdateSerializer,
        responses={
            200: OpenApiResponse(response=UserUpdateResponseSerializer),
            400: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
            401: OpenApiResponse(response=UserUpdateErrorResponseSerializer),
        },
        tags=["User Profile"]
    ),
    put=extend_schema(
        summary="Update My Profile (Full)",
        description="Replaces the entire profile. Prefer PATCH.",
        request=UserUpdateSerializer,
        responses={200: OpenApiResponse(response=UserUpdateResponseSerializer)},
        tags=["User Profile"]
    )
)
class UserProfileUpdateView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserUpdateSerializer

    def get_queryset(self):
        return UserUpdateQuerySet.get_base_queryset()

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        userInstance = self.get_object()

        # Validation happens in the Api layer
        serializer = UserUpdateSerializer(
            userInstance,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)

        # Action receives validated data and returns updated user
        updatedUser = UserUpdateAction.execute(
            userInstance, 
            serializer.validated_data, 
            allowRoleUpdate=False
        )

        # Serialize response in the Api layer
        responseSerializer = UserUpdateSerializer(updatedUser)
        return Response({
            "message": "User profile information updated successfully.",
            "user": responseSerializer.data
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)