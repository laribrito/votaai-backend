from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

# Importing the audit mixin from the Core layer
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.moderation.userProxy import UserProxy

class User(UserProxy, AbstractUser, TimestampSchemaMixin):
    """
    Domain Model: User

    Custom User implementation that extends Django's AbstractUser to include
    auditing capabilities via TimestampSchemaMixin. It enforces mandatory identity
    fields (email, names) and provides helper properties for Role-Based
    Access Control (RBAC) within the system.
    """
    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ['-created_at']

    first_name = models.CharField(
        _("first name"),
        max_length=150,
        blank=False,
        null=False
    )
    last_name = models.CharField(
        _("last name"),
        max_length=150,
        blank=False,
        null=False
    )
    email = models.EmailField(
        _("email address"),
        unique=True,
        blank=False
    )
