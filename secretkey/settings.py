import os

from django import conf
from django.utils.encoding import python_2_unicode_compatible

from secretkey import errors


class SecureSettings(conf.Settings):
    """
    Wraps a settings module so that SECRET_KEY cannot be set within the given
    settings module. Use this when configuring settings manually, otherwise use
    secretkey.settings.configure() in your manage.py and wsgi modules.

    The SECRET_KEY setting is loaded lazily in this class so that checks can be
    performed on the file first.
    """
    def __init__(self, settings_module):
        super(SecureSettings, self).__init__(settings_module)
        if not self.SECRET_KEY_FILE:
            raise conf.ImproperlyConfigured(
                "The SECRET_KEY_FILE setting must not be empty")

    def get_secret_key(self):
        try:
            with open(self.SECRET_KEY_FILE) as secret_key_file:
                return secret_key_file.read()
        except IOError as e:
            raise errors.SecretKeyFileNotFound(e)

    def _get_secret_key(self):
        # The super.__init__ method requires that SECRET_KEY is set, so give
        # it an object that will evaulate True when evaulated boolean-wise but
        # still cannot be evaulated as a string.
        if not conf.settings.configured:
            return UnusableSecretKey()
        if not hasattr(self, '_secret_key'):
            self._secret_key = self.get_secret_key()
        return self._secret_key

    def _set_secret_key(self, value):
        if not conf.settings.configured:
            return
        raise ValueError("The SECRET_KEY setting is read-only")

    def configure(self, **options):
        for name, value in options.iteritems():
            setattr(self, name, value)
        # Unfortunately LazySettings has no public API for extending the base
        # Settings class, so we have to override _wrapped here instead of
        # calling configure()
        conf.settings._wrapped = self

    SECRET_KEY = property(_get_secret_key, _set_secret_key)


@python_2_unicode_compatible
class UnusableSecretKey(object):
    def __str__(self):
        err = "SECRET_KEY cannot be used before settings are configured."
        raise ValueError(err)


def configure_secure():
    """
    Configures settings from DJANGO_SETTINGS_MODULE using SecureSettings().
    This wraps a settings module so that SECRET_KEY cannot be set within the
    given settings module.

    Use this function wherever you initialize Django, such as manage.py, wsgi
    modules, etc.
    """
    if conf.settings.configured:
        return

    settings_mod = os.environ.get(conf.ENVIRONMENT_VARIABLE)
    if not settings_mod:
        msg = "You must define the environment variable %s"
        raise conf.ImproperlyConfigured(msg % conf.ENVIRONMENT_VARIABLE)

    settings = SecureSettings(settings_mod)
    conf.settings.configure(settings)
