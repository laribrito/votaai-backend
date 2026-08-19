from django.apps import AppConfig

class InfrastructureConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Infrastructure'
    verbose_name = 'Infrastructure'

    def ready(self):
        # Django needs to import these modules to register signal receivers.
        # Add new signal handlers here as your infrastructure grows.
        import Infrastructure.signals.passwordSignal         # noqa: F401 — sends password reset emails
        import Infrastructure.signals.userInvitationSignal  # noqa: F401 — sends user invitation emails
