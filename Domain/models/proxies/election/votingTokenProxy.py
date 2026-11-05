import logging
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from Infrastructure.services.seCryptoService import SECryptoService

logger = logging.getLogger(__name__)

class VotingTokenProxy:
    """
    Domain Proxy: VotingToken
    Adds domain behavior for single-use voting token management,
    failed attempts tracking, anti-replay nonces, and security audit logging.
    """

    def mark_as_used(self, ip_address: str = None) -> None:
        """
        Marks the token as used without recording exact voting timestamp,
        preventing temporal linkage with anonymous ballot tickets in the database.
        """
        self.is_used = True
        self.used_at = None
        self.used_ip = None
        self.save(update_fields=['is_used', 'used_at', 'used_ip'])

    def record_failed_attempt(self, ip_address: str = None, max_attempts: int = None) -> None:
        """
        Records an invalid or failed access attempt against this voting token.
        Increments failed_attempts, records audit IP and timestamp.
        Logs the failure with current count and maximum allowed from settings/env.
        Locks the token (is_blocked=True) if failed_attempts reaches max_attempts.
        """
        from django.utils import timezone

        if max_attempts is None:
            max_attempts = getattr(settings, 'VOTING_TOKEN_MAX_FAILED_ATTEMPTS', 3)

        self.failed_attempts = (self.failed_attempts or 0) + 1
        self.last_attempt_at = timezone.now()
        if ip_address:
            self.last_attempt_ip = ip_address

        voter_email = getattr(getattr(self, 'voter', None), 'email', 'desconhecido')

        logger.warning(
            f"[VOTING_TOKEN_ATTEMPT] Tentativa de acesso inválida registrada para o eleitor '{voter_email}' "
            f"(IP: {ip_address or 'desconhecido'}). "
            f"Tentativa {self.failed_attempts} de {max_attempts} permitidas antes do bloqueio definitivo."
        )

        if self.failed_attempts >= max_attempts:
            self.is_blocked = True
            self.blocked_at = timezone.now()
            logger.error(
                f"[VOTING_TOKEN_LOCKOUT] TOKEN BLOQUEADO para o eleitor '{voter_email}' "
                f"(IP: {ip_address or 'desconhecido'}). "
                f"Limite máximo configurado no .env ({max_attempts} tentativas) foi atingido."
            )
            self.save(update_fields=['failed_attempts', 'last_attempt_at', 'last_attempt_ip', 'is_blocked', 'blocked_at'])
        else:
            self.save(update_fields=['failed_attempts', 'last_attempt_at', 'last_attempt_ip'])

    def record_successful_attempt(self, machine_public_key: str, nonce: str, ip_address: str = None) -> None:
        """
        Records a successful ballot request.
        Resets failed_attempts, binds machine_public_key and latest nonce.
        Omits exact millisecond timestamp to prevent temporal linkage with anonymous ballot tickets.
        """
        self.failed_attempts = 0
        self.machine_public_key = SECryptoService.to_pem_public_key(machine_public_key)
        self.nonce = nonce
        self.last_attempt_at = None
        self.last_attempt_ip = None

        voter_email = getattr(getattr(self, 'voter', None), 'email', 'desconhecido')
        logger.info(
            f"[VOTING_TOKEN_SUCCESS] Solicitação de cédula bem-sucedida para o eleitor '{voter_email}' "
            f"(IP: {ip_address or 'desconhecido'}). Chave StrongBox e nonce vinculados."
        )
        self.save(update_fields=['failed_attempts', 'machine_public_key', 'nonce', 'last_attempt_at', 'last_attempt_ip'])

    def unblock(self) -> None:
        """Unblocks a locked voting token, clearing failed attempts count."""
        self.is_blocked = False
        self.blocked_at = None
        self.failed_attempts = 0
        self.save(update_fields=['is_blocked', 'blocked_at', 'failed_attempts'])

    @property
    def is_available(self) -> bool:
        """Returns True if token has not yet been used and is not blocked."""
        return not self.is_used and not self.is_blocked

    def __str__(self) -> str:
        voter_email = getattr(getattr(self, 'voter', None), 'email', 'unknown')
        if getattr(self, 'is_blocked', False):
            status_label = _('blocked')
        elif self.is_used:
            status_label = _('used')
        else:
            status_label = _('available')
        return str(_(f"Token for {voter_email} [{status_label}]"))
