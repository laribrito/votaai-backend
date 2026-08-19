from django.contrib.auth.models import User
from knox.models import AuthToken

class AuthService:
    """Encapsulates token management logic using the Knox library."""

    @staticmethod
    def generateTokenForUser(user: User) -> str:
        """Generates a persistable authentication token for the given user."""
        
        # Knox returns a tuple (instance, token), we only need the raw token string.
        _, token_string = AuthToken.objects.create(user)
        
        return token_string
    