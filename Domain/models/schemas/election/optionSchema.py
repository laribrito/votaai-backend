from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.optionProxy import OptionProxy

class Option(OptionProxy, TimestampSchemaMixin):
    """
    Domain Model: Vote Option.
    Belongs to an election Question.
    """
    class Meta:
        verbose_name = _('Option')
        verbose_name_plural = _('Options')
        ordering = ['label']

    label = models.CharField(
        _('label'),
        max_length=255,
        help_text=_('Label or text of the voting option')
    )
    question = models.ForeignKey(
        'Domain.Question',
        on_delete=models.CASCADE,
        related_name='options',
        verbose_name=_('question')
    )
