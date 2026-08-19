from django.contrib import admin
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _

from Domain.models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """
    Django Admin configuration for the User model.

    Displays key identity and access control fields.
    Uses prefetch_related to avoid N+1 on group display.
    """

    listDisplay = ('username', 'first_name', 'last_name', 'email', 'getRoles', 'is_staff', 'is_active')
    listFilter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    searchFields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('-created_at',)
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions & Roles'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'description': _('Assign groups (Roles) and individual permissions.'),
        }),
        (_('Audit Timestamps'), {'fields': ('last_login', 'date_joined', 'created_at', 'updated_at')}),
    )
    readonly_fields = ('created_at', 'updated_at')

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.prefetch_related('groups')

    def formfieldForManytomany(self, db_field, request=None, **kwargs):
        if db_field.name == 'groups':
            kwargs['queryset'] = Group.objects.all().order_by('name')
        return super().formfieldForManytomany(db_field, request=request, **kwargs)

    @admin.display(description=_('Assigned Roles'))
    def getRoles(self, obj):
        return ", ".join(group.name for group in obj.groups.all()) or str(_('No Role Assigned'))
