from django.db import models
from django.utils.translation import gettext_lazy as _


class BallotTicket(models.Model):
    """
    Domain Model: Ballot Ticket (ID de Voto Desacoplado).
    Armazena identificadores anônimos de cédula gerados pelo backend para cada eleição.
    Possui timestamps próprios (created_at, used_at) totalmente isolados de qualquer
    dado do eleitor ou do token de votação, garantindo o sigilo absoluto do voto.
    """
    class Meta:
        verbose_name = _('Ballot Ticket')
        verbose_name_plural = _('Ballot Tickets')
        ordering = ['?']  # Reordenação aleatória padrão (Mixnet / Anti-Timing)

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
    created_at = models.DateTimeField(
        _('created at'),
        auto_now_add=True,
        help_text=_('Timestamp when this ballot ticket was issued.')
    )
    used_at = models.DateTimeField(
        _('used at'),
        null=True,
        blank=True,
        help_text=_('Timestamp when this ballot ticket was consumed.')
    )

    @classmethod
    def shuffle(cls, election_id: int):
        """
        Retorna os tickets da eleição com reordenação / embaralhamento criptográfico aleatório.
        """
        return cls.objects.filter(election_id=election_id).order_by('?')

    def __str__(self) -> str:
        status = 'used' if self.is_used else 'available'
        return f"Ticket {self.id_voto} [Election #{self.election_id}] ({status})"

