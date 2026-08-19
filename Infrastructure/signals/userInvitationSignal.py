from django.conf import settings
from django.dispatch import receiver

from Domain.signals.invitationSignals import userInvited
from Infrastructure.services.emailService import EmailService


@receiver(userInvited)
def sendInvitationEmail(sender, user, uid, token, **kwargs):
    """
    Infrastructure Signal Handler: User Invitation Email.

    Triggered when the 'user_invited' signal is dispatched by UserInvitationActions.
    Constructs the password-setup link using FRONTEND_URL from settings and
    delivers a welcome email via EmailService.

    The email links to the password-reset/confirm flow, which also activates
    the user account on first access.

    Signal payload:
        user  (User): The newly created User instance.
        uid   (str) : Base64-encoded user PK.
        token (str) : Django one-time password reset token.
    """
    baseUrl = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
    activationLink = f"{baseUrl}/redefinir-senha/{uid}/{token}/"
    appName = getattr(settings, 'APP_NAME', 'My App')
    subject = f"Welcome to {appName} — Set Your Password"

    messageHtml = (
        f"<p style='margin-bottom: 20px;'>Hello, <strong>{user.first_name}</strong>!</p>"
        f"<p style='margin-bottom: 30px;'>An account has been created for you at <strong>{appName}</strong>. "
        f"Click the button below to set your password and activate your account.</p>"
        f"<p style='text-align: center; margin: 40px 0;'>"
        f"  <a href='{activationLink}' style='background-color: #2563EB; color: #ffffff; text-decoration: none; "
        f"padding: 12px 28px; border-radius: 6px; font-weight: 500; display: inline-block;'>Set Your Password</a>"
        f"</p>"
        f"<p style='font-size: 14px; color: #6b7280; margin-top: 30px;'>"
        f"If the button doesn't work, copy and paste this link into your browser:<br>"
        f"<a href='{activationLink}' style='color: #2563EB; word-break: break-all;'>{activationLink}</a></p>"
    )

    try:
        EmailService.sendHtmlEmail(
            subject=subject,
            message=messageHtml,
            recipient_list=[user.email],
        )
    except Exception as e:
        print(f"⚠️ SMTP Error (invitation): {e}")