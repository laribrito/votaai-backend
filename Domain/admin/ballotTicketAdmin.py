from django.contrib import admin
from Domain.models import BallotTicket


@admin.register(BallotTicket)
class BallotTicketAdmin(admin.ModelAdmin):
    list_display = ('id_voto', 'election', 'is_used', 'created_at', 'used_at')
    list_filter = ('election', 'is_used', 'created_at')
    search_fields = ('id_voto',)
    readonly_fields = ('id_voto', 'created_at', 'used_at')

