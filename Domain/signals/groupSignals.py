from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from Domain.models.schemas.moderation.userSchema import User

from Domain.models import GroupRoles, DomainPermissions


@receiver(post_migrate)
def createDefaultGroupsAndPermissions(sender, **kwargs):
    """
    Auto-seeds default Groups and Permissions after each migration run.

    Runs only for the 'Domain' app to avoid redundant execution.
    Uses get_or_create to be fully idempotent (safe to run multiple times).

    -----------------------------------------------------------------------
    Template Note:
    -----------------------------------------------------------------------
    Customize the groups and permissions below to match your application's
    RBAC requirements. The current setup ships with 1 core system role:
        - Administrador: full system access

    To add custom permissions:
        1. Add a codename to DomainPermissions (Domain/models/permission_choices.py)
        2. Add it to the permissions list below
        3. Assign it to the correct group
    -----------------------------------------------------------------------
    """
    if sender.name != 'Domain':
        return

    apps = kwargs.get('apps')
    if not apps:
        return

    User = apps.get_model('Domain', 'User')
    userCt = ContentType.objects.get_for_model(User)

    # -----------------------------------------------------------------------
    # Custom permissions — add your own below following this pattern
    # -----------------------------------------------------------------------
    userPermissionsData = [
        (DomainPermissions.CAN_MANAGE_USERS, "Can manage system users"),
        (DomainPermissions.CAN_MANAGE_GROUPS, "Can manage system groups and roles"),
        (DomainPermissions.CAN_MANAGE_PERMISSIONS, "Can manage custom permissions"),
        (DomainPermissions.CAN_DO_SOMETHING, "Can do something (Example)"),
    ]

    for codename, name in userPermissionsData:
        Permission.objects.get_or_create(
            codename=codename,
            content_type=userCt,
            defaults={'name': name}
        )

    # -----------------------------------------------------------------------
    # Group creation
    # -----------------------------------------------------------------------
    admin_group, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)
    example_group, _ = Group.objects.get_or_create(name=GroupRoles.EXAMPLE.value)

    # Administrador: all permissions
    allPerms = Permission.objects.all()
    if allPerms.exists():
        admin_group.permissions.set(allPerms)

    # Grupo Exemplo: demonstração de atribuição de permissão customizada
    examplePerm = Permission.objects.filter(codename=DomainPermissions.CAN_DO_SOMETHING).first()
    if examplePerm:
        example_group.permissions.set([examplePerm])
