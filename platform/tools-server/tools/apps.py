from django.apps import AppConfig


class ToolsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tools'
    verbose_name = "Core Tools Server"

    def ready(self):
        # Import signals
        from . import signals  # noqa: F401
        # Register DRF Spectacular extensions
        from . import spectacular_extensions  # noqa: F401