from django.db import transaction

from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet

class UserUpdateAction:
    """
    Action responsible for orchestrating the user profile update process.
    Receives validated data from the Api layer and returns the updated User instance.
    """

    @staticmethod
    def execute(user_instance, validated_data: dict, allow_role_update: bool = False) -> object:
        """
        Persists validated changes and handles role assignment.
        Returns the updated user instance for the Api layer to serialize.
        """
        with transaction.atomic():
            # 1. Extract roles and permissions before updating standard fields
            roleNames = validated_data.pop('roles', None)
            permissionIdentifiers = validated_data.pop('permissions', None)

            # 2. Save standard fields (first_name, last_name, email, username)
            for attr, value in validated_data.items():
                setattr(user_instance, attr, value)
            user_instance.save()

            # 3. Handle Roles (Groups) Update logic (Admin Only)
            if allow_role_update and roleNames is not None:
                groups = UserUpdateQuerySet.get_groups_by_names(roleNames)
                if groups:
                    user_instance.groups.set(groups)

            # 4. Handle Direct Permissions Update logic (Admin Only)
            if allow_role_update and permissionIdentifiers is not None:
                from Controllers.querysets.permission.permission_queryset import PermissionQuerySet
                from django.contrib.auth.models import Permission
                perms = PermissionQuerySet(model=Permission).by_codenames_or_ids(permissionIdentifiers)
                user_instance.user_permissions.set(perms)

            return user_instance