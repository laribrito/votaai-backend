from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.voteProxy import VoteProxy

class Vote(VoteProxy, TimestampSchemaMixin):
    """
    Domain Model: Encrypted Vote.
    Stores anonymous, encrypted ballots deposited in an election.
    """
    class Meta:
        verbose_name = _('Vote')
        verbose_name_plural = _('Votes')
        ordering = ['-created_at']

    id_generated = models.CharField(
        _('generated ID'),
        max_length=255,
        unique=True,
        help_text=_('Unique identifier for the vote')
    )
    content = models.TextField(
        _('encrypted content'),
        help_text=_('Encrypted payload of the vote cast by the voter')
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='votes',
        verbose_name=_('election')
    )
