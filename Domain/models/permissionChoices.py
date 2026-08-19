from Domain.apps import DomainConfig


class PermissionMeta(type):
    """
    Metaclass that automatically generates prefixed permission strings (FULL_*)
    for every raw permission codename defined on the class.
    Ex: CAN_MANAGE_USERS -> FULL_CAN_MANAGE_USERS = f'{DomainConfig.name}.can_manage_users'
    """
    def __new__(mcs, name, bases, namespace):
        prefix = namespace.get('PREFIX', DomainConfig.name)
        for key, value in list(namespace.items()):
            if isinstance(value, str) and not key.startswith('_') and key != 'PREFIX' and not key.startswith('FULL_'):
                namespace[f'FULL_{key}'] = f'{prefix}.{value}'
        return super().__new__(mcs, name, bases, namespace)


class DomainPermissions(metaclass=PermissionMeta):
    """
    Centralized constants for custom permission strings in the Domain app.
    Prevents repetition of hardcoded strings across views, signals, and querysets.

    Usage:
        # In a permission class:
        request.user.has_perm(DomainPermissions.FULL_CAN_MANAGE_USERS)

    To add new permissions:
        1. Add the raw codename constant here (e.g., CAN_DO_SOMETHING = 'can_do_something')
        2. The prefixed version FULL_CAN_DO_SOMETHING = f'{DomainConfig.name}.can_do_something' is automatically generated!
        3. Register it in Domain/signals/group_signals.py via post_migrate
        4. Create a BasePermission class in Infrastructure/permissions/
    """
    PREFIX = DomainConfig.name

    # ---------------------------------------------------------------------------
    # Raw permission codenames
    # (FULL_* versions prefixed with 'Domain.' are automatically created via PermissionMeta)
    # ---------------------------------------------------------------------------
    CAN_MANAGE_USERS = 'can_manage_users'
    CAN_MANAGE_GROUPS = 'can_manage_groups'
    CAN_MANAGE_PERMISSIONS = 'can_manage_permissions'
    CAN_DO_SOMETHING = 'can_do_something'

