from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from Domain.models.groupChoices import GroupRoles

class UserProxy:
    """
    Domain Proxy: User

    Proxy model that adds domain-specific behavior (RBAC helpers,
    business constraints) on top of User without touching the DB schema.

    Proxy models are ideal for adding computed properties and validation
    logic while keeping the schema model clean.
    """
    def __str__(self) -> str:
        fullName = self.get_full_name()
        displayName = fullName if fullName else self.username
        groupNames = [group.name for group in self.groups.all()]
        groupsStr = ', '.join(groupNames) if groupNames else str(_('No Groups'))
        return f"{displayName} - ({groupsStr})"

    # ------------------------------------------------------------------
    # RBAC helpers — use these in views/actions instead of raw group checks
    # ------------------------------------------------------------------

    @property
    def isAdmin(self) -> bool:
        return self.is_superuser or self.groups.filter(name=GroupRoles.ADMIN.value).exists()

    # ------------------------------------------------------------------
    # Business constraints
    # ------------------------------------------------------------------

    def clean(self):
        super().clean()
        if self.pk:
            groups = self.groups.all()
            if any(group.name == GroupRoles.ADMIN.value for group in groups) and len(groups) > 1:
                raise ValidationError(_("Administrators cannot have any other roles."))

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)