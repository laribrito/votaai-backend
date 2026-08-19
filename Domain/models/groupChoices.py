from django.db import models
from django.utils.translation import gettext_lazy as _

class GroupRoles(models.TextChoices):
    """
    Centralized Role (Group) definitions for the system.

    These values must match the Group names in the database, which are
    seeded automatically via the post_migrate signal in Domain/signals/group_signals.py.

    To add a new role:
        1. Add a new entry here.
        2. Update group_signals.py to create it on post_migrate.
        3. Assign relevant permissions to the new group there.
    """
    ADMIN = 'Administrador', _('Administrador')
    EXAMPLE = 'Grupo Exemplo', _('Grupo Exemplo')
