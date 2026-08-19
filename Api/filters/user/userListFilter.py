import django_filters
from Domain.models.schemas.moderation.userSchema import User

class UserListFilter(django_filters.FilterSet):

    search = django_filters.CharFilter(method='filterSearch')
    role = django_filters.CharFilter(field_name='groups__name', lookup_expr='iexact')
    is_active = django_filters.BooleanFilter(field_name='is_active')

    class Meta:
        model = User
        fields = ['role', 'is_active']

    def filterSearch(self, queryset, name, value):
        return queryset.searchByTerm(value)