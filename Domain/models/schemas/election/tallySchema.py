from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.tallyProxy import TallyProxy

class Tally(TallyProxy, TimestampSchemaMixin):
    """
    Domain Model: Tally (Apuração).
    Stores election results and cryptographic audit hash.
    """
    class Meta:
        verbose_name = _('Tally')
        verbose_name_plural = _('Tallies')
        ordering = ['-tally_datetime']

    tally_hash = models.CharField(
        _('tally hash'),
        max_length=255,
        help_text=_('Cryptographic audit hash verifying the tally computation')
    )
    tally_datetime = models.DateTimeField(
        _('tally date and time'),
        default=timezone.now,
        help_text=_('Date and time when the tally was performed')
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='tallies',
        verbose_name=_('election')
    )
