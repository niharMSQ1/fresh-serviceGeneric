from django.apps import AppConfig


class FreshserviceappConfig(AppConfig):
    name = 'freshserviceapp'

    def ready(self):
        from .scheduler import start_scheduler
        start_scheduler()
