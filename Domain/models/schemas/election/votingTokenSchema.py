from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.votingTokenProxy import VotingTokenProxy


class VotingToken(VotingTokenProxy, TimestampSchemaMixin):
    """
    Domain Model: Voting Token.
    Single-use token sent via email to each electoral college voter.
    Once consumed (is_used=True), it cannot be reused.
    The raw token is never stored — only its SHA-256 hash is persisted.
    """

    class Meta:
        verbose_name = _('Voting Token')
        verbose_name_plural = _('Voting Tokens')
        ordering = ['-created_at']

    token_hash = models.CharField(
        _('token hash'),
        max_length=64,
        unique=True,
        help_text=_('SHA-256 hash of the raw token. The raw value is never stored.')
    )
    voter = models.ForeignKey(
        'Domain.ElectoralCollege',
        on_delete=models.CASCADE,
        related_name='voting_tokens',
        verbose_name=_('voter')
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='voting_tokens',
        verbose_name=_('election')
    )
    is_used = models.BooleanField(
        _('is used'),
        default=False,
        help_text=_('True after the token has been consumed to cast a vote.')
    )
    used_at = models.DateTimeField(
        _('used at'),
        null=True,
        blank=True,
        help_text=_('Timestamp when the token was consumed.')
    )
    used_ip = models.GenericIPAddressField(
        _('used from IP'),
        null=True,
        blank=True,
        help_text=_('IP address from which the token was consumed (forensic log).')
    )
