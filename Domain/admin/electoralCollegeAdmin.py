from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege


class ElectoralCollegeInline(admin.TabularInline):
    model = ElectoralCollege
    extra = 0
    fields = ('full_name', 'email', 'nickname', 'has_voted', 'email_sent', 'email_sent_at')
    readonly_fields = ('has_voted', 'email_sent', 'email_sent_at')


@admin.register(ElectoralCollege)
class ElectoralCollegeAdmin(admin.ModelAdmin):
    list_display = ('id', 'election', 'full_name', 'email', 'nickname', 'has_voted', 'email_sent', 'email_sent_at')
    list_filter = ('election', 'has_voted', 'email_sent')
    search_fields = ('full_name', 'email', 'nickname')
    readonly_fields = ('email_sent_at',)
    actions = ['resend_voting_email']

    @admin.action(description=_('Reenviar e-mail de votação com novo token'))
    def resend_voting_email(self, request, queryset):
        from Infrastructure.services.votingTokenService import VotingTokenService
        count = 0
        for voter in queryset:
            if not voter.has_voted:
                count += VotingTokenService.generate_and_dispatch(voter, voter.election)
        self.message_user(request, f"{count} e-mail(s) de votação enviado(s) com sucesso.")
