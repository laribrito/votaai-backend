from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.electionProxy import ElectionProxy

class ElectionStatus(models.TextChoices):
    CREATED = 'CREATED', _('Created')
    STARTED = 'STARTED', _('Started')
    CLOSED = 'CLOSED', _('Closed')
    TALLIED = 'TALLIED', _('Tallied')


class Election(ElectionProxy, TimestampSchemaMixin):
    """
    Domain Model: Election.
    Central entity according to the ERD:
    - title, public_key, start_datetime, end_datetime, created_by, key_handle.
    """
    class Meta:
        verbose_name = _('Election')
        verbose_name_plural = _('Elections')
        ordering = ['-created_at']

    title = models.CharField(
        _('title'),
        max_length=255,
        help_text=_('Title of the election')
    )
    public_key = models.TextField(
        _('public key'),
        help_text=_('Election public key for encrypting ballots')
    )
    start_datetime = models.DateTimeField(
        _('start date and time'),
        null=True,
        blank=True,
        help_text=_('Voting start date and time')
    )
    end_datetime = models.DateTimeField(
        _('end date and time'),
        null=True,
        blank=True,
        help_text=_('Voting end date and time')
    )
    key_handle = models.CharField(
        _('key handle'),
        max_length=255,
        unique=True,
        help_text=_('Unique election key handle in the machine storage')
    )
    machine_fingerprint = models.CharField(
        _('machine fingerprint'),
        max_length=64,
        blank=True,
        default='',
        db_index=True,
        help_text=_('Non-replicable public SHA-256 fingerprint of the physical machine public key')
    )
    machine_signature = models.TextField(
        _('machine signature'),
        blank=True,
        default='',
        help_text=_('Digital signature produced by the desktop machine')
    )
    private_key = models.TextField(
        _('private key'),
        null=True,
        blank=True,
        help_text=_('Election private key revealed after tallying for public verification')
    )
    status = models.CharField(
        _('status'),
        max_length=30,
        choices=ElectionStatus.choices,
        default=ElectionStatus.CREATED
    )
    created_by = models.ForeignKey(
        'Domain.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='elections',
        verbose_name=_('created by')
    )

    def clean(self):
        super().clean()
        if not self.created_by:
            raise ValidationError({'created_by': _('Election must have an associated creator user.')})

    def save(self, *args, **kwargs):
        if not self.created_by:
            raise ValueError(_('Election must be associated with a user (created_by cannot be null).'))
        if self.public_key:
            try:
                from Infrastructure.services.seCryptoService import SECryptoService
                self.public_key = SECryptoService.to_pem_public_key(self.public_key)
            except Exception:
                pass
        if not self.machine_fingerprint and self.created_by and getattr(self.created_by, 'machine_public_key', None):
            try:
                from Infrastructure.services.seCryptoService import SECryptoService
                self.machine_fingerprint = SECryptoService.get_machine_fingerprint(self.created_by.machine_public_key)
            except Exception:
                pass
        super().save(*args, **kwargs)
