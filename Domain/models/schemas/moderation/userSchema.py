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
    device_id = models.CharField(
        _('device id'),
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
    email_verified = models.BooleanField(
        _('email verified'),
        default=False,
        help_text=_('Indicates whether the administrator email has been verified during registration')
    )
    email_verification_code_hash = models.CharField(
        _('email verification code hash'),
        max_length=128,
        blank=True,
        null=True,
        help_text=_('SHA-256 hash of the 6-digit email verification code')
    )
    email_verification_expires_at = models.DateTimeField(
        _('email verification expires at'),
        blank=True,
        null=True,
        help_text=_('Expiration timestamp for the email verification code')
    )
    email_verification_attempts = models.PositiveSmallIntegerField(
        _('email verification attempts'),
        default=0,
        help_text=_('Number of failed email verification attempts for the current code')
    )

    def save(self, *args, **kwargs):
        if self.machine_public_key:
            try:
                from Infrastructure.services.seCryptoService import SECryptoService
                self.machine_public_key = SECryptoService.to_pem_public_key(self.machine_public_key)
            except Exception:
                pass
        super().save(*args, **kwargs)
