from django.contrib import admin
from Domain.models import BallotTicket


@admin.register(BallotTicket)
class BallotTicketAdmin(admin.ModelAdmin):
    list_display = ('id', 'id_voto', 'election', 'is_used')
    list_filter = ('election', 'is_used')
    search_fields = ('id_voto',)
    readonly_fields = ('id', 'id_voto')

