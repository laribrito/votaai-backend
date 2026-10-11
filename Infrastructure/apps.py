from django.apps import AppConfig

class InfrastructureConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Infrastructure'
    verbose_name = 'Infrastructure'

    def ready(self):
        # Django needs to import signal receivers if registered.
        pass
