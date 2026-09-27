from django.contrib.auth.hashers import make_password, check_password
from django.utils.translation import gettext_lazy as _

class ElectoralCollegeProxy:
    """
    Domain Proxy: ElectoralCollege
    Proxy mixin that adds domain-specific behavior, password hashing helpers,
    first name extraction, and string representation on top of ElectoralCollege
    without polluting the DB schema.
    """

    def set_password(self, raw_password: str) -> None:
        """Stores only the secure cryptographic hash of the voter password."""
        if raw_password:
            self.password = make_password(raw_password)
        else:
            self.password = ''

    def check_password(self, raw_password: str) -> bool:
        """Verifies a raw password against the stored cryptographic hash."""
        password = getattr(self, 'password', None)
        if not password:
            return False
        return check_password(raw_password, password)

    def get_first_name(self) -> str:
        """
        Extracts the first name from the voter's full_name.
        """
        full_name = getattr(self, 'full_name', '') or ''
        parts = full_name.strip().split()
        return parts[0] if parts else ''

    @property
    def first_name(self) -> str:
        """Returns the voter's first name (derived from full_name or nickname)."""
        return self.get_first_name() or getattr(self, 'nickname', '')

    def mark_email_sent(self) -> None:
        """Marks that the voting invitation email was successfully sent to this voter."""
        from django.utils import timezone
        self.email_sent = True
        self.email_sent_at = timezone.now()
        self.save(update_fields=['email_sent', 'email_sent_at'])

    def clean(self):
        super().clean()
        if not getattr(self, 'full_name', '') and getattr(self, 'email', ''):
            try:
                from Domain.models.schemas.moderation.userSchema import User
                matched = User.objects.filter(email__iexact=self.email).first()
                if matched:
                    name_parts = [matched.first_name, matched.last_name]
                    user_name = " ".join(p for p in name_parts if p).strip()
                    if user_name:
                        self.full_name = user_name
            except Exception:
                pass

        first = self.get_first_name()
        if first:
            self.nickname = first

    def save(self, *args, **kwargs):
        """
        Ensures nickname is always the first name extracted from full_name.
        """
        if not getattr(self, 'full_name', '') and getattr(self, 'email', ''):
            try:
                from Domain.models.schemas.moderation.userSchema import User
                matched = User.objects.filter(email__iexact=self.email).first()
                if matched:
                    name_parts = [matched.first_name, matched.last_name]
                    user_name = " ".join(p for p in name_parts if p).strip()
                    if user_name:
                        self.full_name = user_name
            except Exception:
                pass

        first = self.get_first_name()
        if first:
            self.nickname = first
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        has_voted_str = _('Yes') if getattr(self, 'has_voted', False) else _('No')
        email_sent_str = _('Yes') if getattr(self, 'email_sent', False) else _('No')
        return str(_("%(full_name)s (%(email)s) - Voted: %(has_voted)s - Email sent: %(email_sent)s") % {
            'full_name': getattr(self, 'full_name', ''),
            'email': getattr(self, 'email', ''),
            'has_voted': has_voted_str,
            'email_sent': email_sent_str
        })

