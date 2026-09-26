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
        _('first name'),
        max_length=150,
        blank=True,
        default=''
    )
    last_name = models.CharField(
        _('last name'),
        max_length=150,
        blank=True,
        default=''
    )
    email = models.EmailField(
        _('email address'),
        unique=True,
        blank=False
    )
    machine_public_key = models.TextField(
        _('machine public key'),
        blank=True,
        null=True,
        help_text=_('Machine RSA public key linked to the user for hardware validation and cryptography')
    )
    machine_user = models.CharField(
        _('machine user'),
        max_length=64,
        blank=True,
        null=True,
        db_index=True,
        help_text=_('Unique, OS-agnostic identifier of the physical device or machine')
    )
    totp_secret = models.CharField(
        _('TOTP secret'),
        max_length=64,
        blank=True,
        null=True,
        help_text=_('Base32 secret for two-factor authentication (TOTP)')
    )
