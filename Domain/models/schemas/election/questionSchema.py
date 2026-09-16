from django.db import models
from django.utils.translation import gettext_lazy as _
from Core.schemaMixins.timestampSchemaMixin import TimestampSchemaMixin
from Domain.models.proxies.election.questionProxy import QuestionProxy

class Question(QuestionProxy, TimestampSchemaMixin):
    """
    Domain Model: Election Question.
    Belongs to an Election and has multiple vote Options.
    """
    class Meta:
        verbose_name = _('Question')
        verbose_name_plural = _('Questions')
        ordering = ['order', 'id']

    question = models.TextField(
        _('question'),
        help_text=_('Question text or ballot statement')
    )
    order = models.PositiveIntegerField(
        _('order'),
        default=1,
        help_text=_('Display order of the question on the ballot')
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='questions',
        verbose_name=_('election')
    )
