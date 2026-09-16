from django.contrib import admin
from Domain.models.schemas.election.electionSchema import Election
from Domain.admin.questionAdmin import QuestionInline
from Domain.admin.electoralCollegeAdmin import ElectoralCollegeInline


@admin.register(Election)
class ElectionAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'title',
        'status',
        'start_datetime',
        'end_datetime',
        'created_by',
        'questions_count',
        'options_count',
        'created_at'
    )
    list_filter = ('status', 'created_at')
    search_fields = ('title', 'key_handle')
    readonly_fields = ('created_at', 'updated_at', 'questions_count', 'options_count')
    inlines = [QuestionInline, ElectoralCollegeInline]
