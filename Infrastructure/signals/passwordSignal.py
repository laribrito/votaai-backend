from django.conf import settings
from django.dispatch import receiver

from Domain.signals.authSignals import passwordResetRequested
from Infrastructure.services.emailService import EmailService

@receiver(passwordResetRequested)
def sendPasswordResetEmail(sender, user, uid, token, **kwargs):
    """
    Infrastructure Signal Handler: Password Reset Email.

    Triggered when the 'password_reset_requested' signal is dispatched by
    PasswordManagementActions.request_reset().

    Constructs the reset link using FRONTEND_URL from settings and delivers
    the email via EmailService.

    Signal payload:
        user  (User): The User requesting the reset.
        uid   (str) : Base64-encoded user PK.
        token (str) : Django one-time password reset token.
    """
    baseUrl = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
    appName = getattr(settings, 'APP_NAME', 'My App')
    resetLink = f"{baseUrl}/redefinir-senha/{uid}/{token}/"
    subject = "Password Reset Request"

    messageHtml = (
        f"<p style='margin-bottom: 20px;'>Hello, <strong>{user.first_name}</strong>,</p>"
        f"<p style='margin-bottom: 30px;'>You recently requested to reset your password for your "
        f"<strong>{appName}</strong> account.</p>"
        f"<p style='text-align: center; margin: 40px 0;'>"
        f"  <a href='{resetLink}' style='background-color: #2563EB; color: #ffffff; text-decoration: none; "
        f"padding: 12px 28px; border-radius: 6px; font-weight: 500; display: inline-block;'>Reset Password</a>"
        f"</p>"
        f"<p style='font-size: 14px; color: #6b7280; margin-top: 30px;'>"
        f"If you did not request a password reset, please ignore this email or contact support.</p>"
        f"<p style='font-size: 12px; color: #9ca3af; margin-top: 20px;'>"
        f"If the button doesn't work, copy and paste this link into your browser:<br>"
        f"<a href='{resetLink}' style='color: #2563EB; word-break: break-all;'>{resetLink}</a></p>"
    )

    try:
        EmailService.sendHtmlEmail(
            subject=subject,
            message=messageHtml,
            recipient_list=[user.email],
        )
    except Exception as e:
        print(f"⚠️ SMTP Error (password reset): {e}")