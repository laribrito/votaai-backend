from typing import Any, Dict, List, Optional

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

class EmailService:
    """
    Infrastructure service for HTML email rendering and delivery.
    """

    @staticmethod
    def sendHtmlEmail(
        subject: str,
        message: str,
        recipient_list: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if context is None:
            context = {}

        context['subject'] = subject
        context['message'] = message

        try:
            htmlContent = render_to_string('emails/base_email.html', context)
            textContent = strip_tags(htmlContent)

            email = EmailMultiAlternatives(
                subject=subject,
                body=textContent,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=recipient_list,
            )

            email.attach_alternative(htmlContent, 'text/html')
            email.send(fail_silently=False)
            return True

        except Exception as e:
            print(f'EmailService: Failed to send HTML email. Error: {e}')
            return False