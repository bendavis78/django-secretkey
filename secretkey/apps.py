from django import apps

import secretkey.checks  # NOQA


class AppConfig(apps.AppConfig):
    name = 'secretkey'
    verbose_name = 'Secure secret key management'
