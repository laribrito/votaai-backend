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
        """Returns the voter's first name (derived from nickname or full_name)."""
        return getattr(self, 'nickname', '') or self.get_first_name()

    def save(self, *args, **kwargs):
        """
        Ensures nickname is automatically populated with the voter's first name
        extracted from full_name if not already populated.
        """
        if hasattr(self, 'full_name') and self.full_name and not getattr(self, 'nickname', None):
            self.nickname = self.get_first_name()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        has_voted_str = _('Yes') if getattr(self, 'has_voted', False) else _('No')
        return str(_("%(full_name)s (%(email)s) - Voted: %(has_voted)s") % {
            'full_name': getattr(self, 'full_name', ''),
            'email': getattr(self, 'email', ''),
            'has_voted': has_voted_str
        })

