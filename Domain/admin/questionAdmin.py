from django.contrib import admin
from Domain.models.schemas.election.questionSchema import Question
from Domain.admin.optionAdmin import OptionInline

class QuestionInline(admin.StackedInline):
    model = Question
    extra = 0


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'election', 'order', 'question')
    list_filter = ('election',)
    search_fields = ('question',)
    inlines = [OptionInline]
