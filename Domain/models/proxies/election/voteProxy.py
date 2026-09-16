from django.utils.translation import gettext_lazy as _

class VoteProxy:
    """
    Domain Proxy: Vote
    Proxy mixin that adds domain-specific behavior and string representation
    on top of Vote without polluting the DB schema.
    """

    def __str__(self) -> str:
        id_gen = getattr(self, 'id_generated', '')
        election_id = getattr(self, 'election_id', '')
        return str(_("Vote %(id_gen)s - Election #%(election_id)s") % {
            'id_gen': id_gen,
            'election_id': election_id
        })

