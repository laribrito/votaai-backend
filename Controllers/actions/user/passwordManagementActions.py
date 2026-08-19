from Domain.models.schemas.moderation.userSchema import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

# Import the signal
from Domain.signals import passwordResetRequested



class PasswordManagementActions:
    """
    Handles business logic for password management.
    Covers: Forgot Password, First Login Setup, and Authenticated Change.
    """

    @staticmethod
    def requestReset(email):
        """
        Generates a password reset token and triggers the email notification via Signal.
        """
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Security Rule: Never reveal if an email exists.
            return {"message": "If an account exists with this email, a reset link has been sent."}

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Notify via Signal: The observer decides how to build the link.
        passwordResetRequested.send(
            sender=PasswordManagementActions,
            user=user,
            uid=uid,
            token=token
        )

        return {"message": "If an account exists with this email, a reset link has been sent."}

    @staticmethod
    def confirmReset(data):
        """
        Validates the UID and Token, then sets the new password.
        Also activates the user if they are inactive (handles first-login invitation flow).
        This single method replaces the old separate 'complete_setup' action.
        """
        uid = data.get('uid')
        token = data.get('token')
        newPassword = data.get('newPassword')

        try:
            uidDecoded = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uidDecoded)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValueError("Invalid reset link.")

        if not default_token_generator.check_token(user, token):
            raise ValueError("Invalid or expired token.")

        user.set_password(newPassword)

        # Activate the user if they were invited but haven't set a password yet.
        # For already active users (forgot password flow), this is a harmless no-op.
        if not user.is_active:
            user.is_active = True

        user.save()

        return {"message": "Password has been reset successfully."}

    @staticmethod
    def changePassword(user, data):
        """
        Changes the password for an authenticated user.
        """
        oldPassword = data.get('oldPassword')
        newPassword = data.get('newPassword')

        if not user.check_password(oldPassword):
            raise ValueError("The old password is incorrect.")

        user.set_password(newPassword)
        user.save()

        return {"message": "Password updated successfully."}