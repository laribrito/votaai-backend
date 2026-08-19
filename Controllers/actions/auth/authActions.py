from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from Controllers.actions.auth.authService import AuthService

class AuthActions:
    """
    Orchestrates the login workflow, validation logic, and error handling.
    """

    @staticmethod
    def login(data: dict) -> dict:
        """
        Validates credentials, checks account status, and generates an auth token.
        
        Returns:
            dict: A raw dictionary containing the 'user' object and 'token' string.
                  (Formatting is handled by the Api layer).
        """
        username = data.get('username')
        password = data.get('password')

        # 1. Validate Credentials using Django's internal QuerySet/Auth backend
        user = authenticate(username=username, password=password)

        if user is None:
            from Domain.models.schemas.moderation.userSchema import User
            inactiveUser = User.objects.filter(username=username, is_active=False).first()
            if inactiveUser and inactiveUser.check_password(password):
                raise PermissionDenied("This account is deactivated. Please contact the administrator.")
            raise AuthenticationFailed("Invalid username or password. Please try again.")

        # 2. Check Account Status
        if not user.is_active:
            raise PermissionDenied("This account is deactivated. Please contact the administrator.")

        # 3. Generate Token via Domain Service
        token = AuthService.generate_token_for_user(user)

        # Return raw objects. Separation of Concerns: Actions don't worry about JSON structure.
        return {
            "user": user,
            "token": token
        }
    