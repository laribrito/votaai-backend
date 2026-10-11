from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.electoralCollegeProxy import ElectoralCollegeProxy

class ElectoralCollege(ElectoralCollegeProxy, TimestampSchemaMixin):
    """
    Domain Model: Electoral College (Voter for an Election).
    Represents an eligible voter in a specific election,
    tracking voting participation status (has_voted) and storing only hashed passwords.
    """
    class Meta:
        verbose_name = _('Electoral College Voter')
        verbose_name_plural = _('Electoral College')
        ordering = ['full_name']
        constraints = [
            models.UniqueConstraint(
                fields=['election', 'email'],
                name='unique_voter_per_election'
            )
        ]

    full_name = models.CharField(
        _('full name'),
        max_length=255,
        help_text=_('Full name of the voter')
    )
    email = models.EmailField(
        _('email'),
        help_text=_('Email of the voter')
    )
    nickname = models.CharField(
        _('nickname'),
        max_length=150,
        blank=True,
        default='',
        help_text=_('First name of the voter extracted from full name')
    )
    password = models.CharField(
        _('password hash'),
        max_length=255,
        blank=True,
        default='',
        help_text=_('Hashed password of the voter (never stored in plaintext)')
    )
    has_voted = models.BooleanField(
        _('has voted'),
        default=False,
        help_text=_('Indicates whether this voter has already cast their ballot')
    )
    email_sent = models.BooleanField(
        _('email sent'),
        default=False,
        help_text=_('Indicates whether the voting email has been sent to this voter')
    )
    email_sent_at = models.DateTimeField(
        _('email sent at'),
        null=True,
        blank=True,
        help_text=_('Timestamp of the last email sent to this voter')
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='electoral_college',
        verbose_name=_('election')
    )
