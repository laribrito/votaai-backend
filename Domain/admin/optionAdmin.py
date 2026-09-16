from django.contrib import admin
from Domain.models.schemas.election.optionSchema import Option


class OptionInline(admin.TabularInline):
    model = Option
    extra = 0


@admin.register(Option)
class OptionAdmin(admin.ModelAdmin):
    list_display = ('id', 'question', 'label')
    search_fields = ('label',)
