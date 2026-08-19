from django.apps import AppConfig


class DomainConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Domain'
    verbose_name = 'Domain'

    def ready(self):
        # Django needs to import these modules to register signal receivers.
        # Add new signal modules here as your domain grows.
        import Domain.signals.userStatusSignal  # noqa: F401 — revokes Knox tokens on user deactivation
        import Domain.signals.groupSignals        # noqa: F401 — seeds default Groups/Permissions on post_migrate
