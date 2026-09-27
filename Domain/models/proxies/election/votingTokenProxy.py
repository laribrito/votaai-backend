from django.utils.translation import gettext_lazy as _


class VotingTokenProxy:
    """
    Domain Proxy: VotingToken
    Adds domain behavior for single-use voting token management.
    """

    def mark_as_used(self, ip_address: str = None) -> None:
        """Marks the token as used, recording timestamp and optional IP address."""
        from django.utils import timezone
        self.is_used = True
        self.used_at = timezone.now()
        if ip_address:
            self.used_ip = ip_address
        self.save(update_fields=['is_used', 'used_at', 'used_ip'])

    @property
    def is_available(self) -> bool:
        """Returns True if token has not yet been used."""
        return not self.is_used

    def __str__(self) -> str:
        voter_email = getattr(getattr(self, 'voter', None), 'email', 'unknown')
        used_label = _('used') if self.is_used else _('available')
        return str(_(f"Token for {voter_email} [{used_label}]"))
