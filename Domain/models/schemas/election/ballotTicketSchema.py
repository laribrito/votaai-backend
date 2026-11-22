import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _


class BallotTicket(models.Model):
    """
    Domain Model: Ballot Ticket (ID de Voto Desacoplado).
    Armazena identificadores anônimos de cédula gerados pelo backend para cada eleição,
    com chave primária UUIDv4 não ordenável e sem quaisquer timestamps,
    garantindo o sigilo absoluto do voto contra correlação temporal ou ordinal.
    """
    class Meta:
        verbose_name = _('Ballot Ticket')
        verbose_name_plural = _('Ballot Tickets')

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    election = models.ForeignKey(
        'Domain.Election',
        on_delete=models.CASCADE,
        related_name='ballot_tickets',
        verbose_name=_('election')
    )
    id_voto = models.CharField(
        _('id voto'),
        max_length=64,
        unique=True,
        db_index=True,
        help_text=_('Randomized ballot ticket identifier issued by the backend.')
    )
    is_used = models.BooleanField(
        _('is used'),
        default=False,
        help_text=_('True once the ballot ticket has been consumed with a deposited vote.')
    )

    def __str__(self) -> str:
        status = 'used' if self.is_used else 'available'
        return f"Ticket {self.id_voto} [Election #{self.election_id}] ({status})"

