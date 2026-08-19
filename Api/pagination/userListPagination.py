from rest_framework.pagination import PageNumberPagination

class UserListPagination(PageNumberPagination):
    """
    Specific pagination configuration for the User List.
    Allows the client to control page size via query param.
    """
    pageSize = 10  # Default to 10 users per page
    pageSizeQueryParam = 'pageSize'
    maxPageSize = 100