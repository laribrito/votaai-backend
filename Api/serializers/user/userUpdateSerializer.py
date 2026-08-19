from rest_framework import serializers
from Domain.models.schemas.moderation.userSchema import User

# Project Imports
from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Base Serializer for user self-updates.
    Contains only fields that a regular user can modify (No Roles).
    Delegates database existence checks to the UserUpdateQuerySet layer.
    """
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username']

    def validateEmail(self, value):
        user = self.instance
        if UserUpdateQuerySet.is_email_taken(value, user.pk):
            raise serializers.ValidationError("This email is already in use by another account.")
        return value

    def validateUsername(self, value):
        user = self.instance
        if UserUpdateQuerySet.is_username_taken(value, user.pk):
            raise serializers.ValidationError("This username is already taken.")
        return value


class UserManagementSerializer(UserUpdateSerializer):
    """
    Extended Serializer for Admin operations.
    Inherits from UserUpdateSerializer and adds the 'roles' and 'permissions' fields.
    """
    roles = serializers.ListField(
        child=serializers.CharField(),
        required=False, 
        allow_empty=False,
        help_text="List of Group names (Roles). List cannot be empty."
    )
    permissions = serializers.ListField(
        child=serializers.JSONField(),
        required=False,
        allow_empty=True,
        help_text="List of direct custom permission IDs or codenames for the user."
    )

    class Meta(UserUpdateSerializer.Meta):
        fields = UserUpdateSerializer.Meta.fields + ['roles', 'permissions']

    def validateRoles(self, value):
        if not value or len(value) == 0:
            raise serializers.ValidationError("The user must have at least one role.")

        if not UserUpdateQuerySet.check_all_roles_exist(value):
            raise serializers.ValidationError("One or more provided roles do not exist.")

        requestUser = self.context.get('requestUser')

        if 'Administrador' in value:
            if not UserUpdateQuerySet.is_admin_user(requestUser):
                raise serializers.ValidationError("Somente Administradores podem atribuir o cargo de Administrador.")
            value = ['Administrador']

        if self.instance and UserUpdateQuerySet.is_admin_user(self.instance) and set(value) != {'Administrador'}:
            raise serializers.ValidationError("Usuários Administradores não podem receber outros cargos.")

        return value


class UserUpdateResponseSerializer(serializers.Serializer):
    """
    Response for User Self-Update (No Roles).
    """
    message = serializers.CharField()
    user = UserUpdateSerializer()  # <--- Uses the serializer WITHOUT roles

class UserManagementResponseSerializer(serializers.Serializer):
    """
    Response for Admin Update (With Roles).
    """
    message = serializers.CharField()
    user = UserManagementSerializer() # <--- Uses the serializer WITH roles

class UserUpdateErrorResponseSerializer(serializers.Serializer):
    """
    Specific error response serializer.
    """
    detail = serializers.CharField()
    