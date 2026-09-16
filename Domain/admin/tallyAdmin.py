from django.contrib import admin
from Domain.models.schemas.election.tallySchema import Tally

@admin.register(Tally)
class TallyAdmin(admin.ModelAdmin):
    list_display = ('id', 'election', 'tally_hash', 'tally_datetime')
    list_filter = ('election',)
    readonly_fields = ('tally_datetime',)
