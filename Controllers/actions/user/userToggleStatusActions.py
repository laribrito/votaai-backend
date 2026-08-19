from Domain.models.schemas.moderation.userSchema import User
from django.shortcuts import get_object_or_404

class UserStatusToggleAction:
    """
    Business logic orchestrator for toggling user status.
    Encapsulates state change and returns a plain dict.
    """

    @staticmethod
    def execute(user_id: int) -> dict:
        """
        Retrieves user, toggles is_active, and returns a plain dict.
        The save() call triggers the Domain observer for security.
        """
        user = get_object_or_404(User, pk=user_id)
        
        # Invert the boolean status
        user.is_active = not user.is_active
        user.save()
        
        # Prepare the return data
        statusLabel = "Active" if user.is_active else "Inactive"
        
        return {
            "message": f"User status updated to {statusLabel.lower()} successfully.",
            "username": user.username,
            "statusLabel": statusLabel
        }