from django.contrib import admin
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege


class ElectoralCollegeInline(admin.TabularInline):
    model = ElectoralCollege
    extra = 0
    fields = ('full_name', 'email', 'nickname', 'has_voted')
    readonly_fields = ('has_voted',)


@admin.register(ElectoralCollege)
class ElectoralCollegeAdmin(admin.ModelAdmin):
    list_display = ('id', 'election', 'full_name', 'email', 'nickname', 'has_voted')
    list_filter = ('election', 'has_voted')
    search_fields = ('full_name', 'email', 'nickname')
