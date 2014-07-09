from django import apps
from django.conf import settings

import secretkey.checks  # NOQA


class AppConfig(apps.AppConfig):
    name = 'secretkey'
    verbose_name = 'Secure secret key management'

    def get_models(self, *args, **kwargs):
        if not settings.SECRET_KEY_STORE_SIGNATURE:
            return ()
        return super(AppConfig, self).get_models(*args, **kwargs)
