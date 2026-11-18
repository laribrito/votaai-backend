from django.contrib import admin
from Domain.models.schemas.election.voteSchema import Vote

@admin.register(Vote)
class VoteAdmin(admin.ModelAdmin):
    list_display = ('id', 'election', 'id_generated')
    list_filter = ('election',)
    search_fields = ('id_generated',)
