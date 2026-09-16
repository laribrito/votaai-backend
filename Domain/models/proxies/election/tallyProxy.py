from django.utils.translation import gettext_lazy as _

class TallyProxy:
    """
    Domain Proxy: Tally
    Proxy mixin that adds domain-specific behavior and string representation
    on top of Tally without polluting the DB schema.
    """

    def __str__(self) -> str:
        election_id = getattr(self, 'election_id', '')
        tally_hash = getattr(self, 'tally_hash', '')[:16]
        tally_dt = getattr(self, 'tally_datetime', '')
        return str(_("Tally for Election #%(election_id)s (%(tally_hash)s...) at %(tally_dt)s") % {
            'election_id': election_id,
            'tally_hash': tally_hash,
            'tally_dt': tally_dt
        })

