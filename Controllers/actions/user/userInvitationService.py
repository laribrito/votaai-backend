from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from Domain.models.schemas.moderation.userSchema import User

class UserInvitationService:
    """
    Domain Service: User Invitation Management.
    
    This service is responsible for the technical orchestration of creating 
    provisional user accounts. It ensures that new users are created securely 
    without an initial password and generates the necessary security tokens 
    for the first-access workflow.
    """

    @staticmethod
    @transaction.atomic
    def createPendingUser(first_name: str, last_name: str, username: str, email: str, role_name: str):
        """
        Creates a new user with an unusable password and assigns a role.
        
        Args:
            first_name (str): The user's first name.
            last_name (str): The user's last name.
            username (str): Unique username for system access.
            email (str): Valid email address for notifications.
            role_name (str): The name of the Group (e.g., 'Administrador', 'Redator') to assign.

        Returns:
            tuple: A tuple containing:
                - user (User): The created User instance.
                - uid (str): Base64 encoded user ID for URL safety.
                - token (str): One-time use security token for password setup.

        Raises:
            ValueError: If the specified role (Group) does not exist.
        """
        # 1. Create the user instance securely
        # We use create_user instead of create to handle password hashing internals,
        # even though we are setting it to unusable immediately after.
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        
        # Security: Ensure the account cannot be accessed until the password is set via the link.
        user.set_unusable_password()
        user.save()

        # 2. Assign the Role (Group)
        try:
            group = Group.objects.get(name=role_name)
            user.groups.add(group)
        except ObjectDoesNotExist:
            # Rollback transaction if the role is invalid to prevent "headless" users
            raise ValueError(f"O cargo '{role_name}' não existe no sistema.")

        # 3. Generate Security Credentials
        # UID: Encodes the Primary Key to base64 to avoid exposing direct DB IDs in URLs.
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Token: Generates a hash using the user's state and timestamp. 
        # This token becomes invalid if the user state changes (e.g., password set) or time expires.
        token = default_token_generator.make_token(user)

        return user, uid, token
    