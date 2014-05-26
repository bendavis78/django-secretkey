from __future__ import unicode_literals

import string
import logging

from django.apps import apps
from django.conf import settings
from django.contrib.sites.models import Site
from django.core.signing import Signer, BadSignature
from django.db import models, connection
from django.utils import timezone
from django.utils.crypto import random
from django.utils.encoding import python_2_unicode_compatible

from secretkey import errors

logger = logging.getLogger(__name__)


class SignatureManager(models.Manager):
    @property
    def current_site(self):
        if not apps.is_installed('django.contrib.sites'):
            return None
        try:
            return Site.objects.get_current()
        except Site.DoesNotExist:
            return None

    def get_current(self, site=None):
        site = site or self.current_site
        objects = self.get_queryset().filter(site=site)
        if objects.count() > 0:
            return objects.latest()
        return None

    def get_all_current_signatures(self):
        def sites_iter():
            yield None
            for site in Site.objects.all():
                yield site
        for site in sites_iter():
            try:
                yield self.get_queryset().filter(site=site).latest()
            except self.model.DoesNotExist:
                pass

    def create_signature(self, site=None, force=False):
        """
        Creates a new stored signature for the current site.

        The signature is used to prevent accidental changes to the secret key.
        If `force` is True, and a current signature exists, this method will
        overwrite the current signature.
        """
        site = site or self.current_site
        if self.get_current(site) and not force:
            raise ValueError("A signature already exists for this site.")
        signer = Signer(settings.SECRET_KEY)
        value = ''.join(random.sample(string.letters, 32))
        signed = signer.sign(value)
        signature = Signature(site=site, signed_value=signed)
        signature.save()
        if site:
            logger.info("Created new signature for site '{0}': {1}".format(
                site, signed))
        else:
            logger.info("Created new signature: ".format(signed))
        return signature

    def db_ready(self):
        """
        Since this app operates around the SECRET_KEY, which is used very early
        in the django startup process, we need the ability to check whether or
        not the schema is up to date. Callers of this method will typically
        continue silently without performing any model operations.
        """
        from django.db.migrations.loader import MigrationLoader
        loader = MigrationLoader(connection)

        app_label = self.model._meta.app_label
        if app_label in loader.unmigrated_apps:
            db_table = self.model._meta.db_table
            return db_table in connection.introspection.table_names()

        # If this app ever has migrations this will need to be implemented
        raise NotImplementedError


@python_2_unicode_compatible
class Signature(models.Model):
    site = models.ForeignKey(Site, null=True)
    date = models.DateTimeField(default=timezone.now)
    signed_value = models.CharField(max_length=128)

    objects = SignatureManager()

    class Meta:
        # There should only ever be one record per site, but we get by latest
        # date as an extra measure.
        get_latest_by = 'date'

    def verify(self):
        """
        Attempts to unsign the signature using the current `SECRET_KEY`. If
        unsigning fails, `SECRET_KEY` has changed, and the exception
        `django.core.signing.BadSignature` will be raised. If `SECRET_KEY_FILE`
        does not exist, `secretkey.errors.SecretKeyFileNotFound` will be
        raised.
        """
        secret_key = settings.SECRET_KEY
        signer = Signer(secret_key)
        signer.unsign(self.signed_value)

    def is_valid(self):
        """
        Performs `self.valid()`, and will return False if either `BadSignature`
        or `SecretKeyFileNotFound` is raised.
        """
        try:
            self.verify()
        except BadSignature:
            return False
        except errors.SecretKeyFileNotFound:
            return False
        return True

    def save(self, *args, **kwargs):
        if not self.site:
            self.site = self._default_manager.current_site
        super(Signature, self).save(*args, **kwargs)

    def __str__(self):
        if self.site:
            fmt = "{site.name}: {date:%Y-%m-%d} ({status})"
        else:
            fmt = "{date:%Y-%m-%d} ({status})"
        return fmt.format(
            date=self.date,
            status=self.is_valid() and 'valid' or 'INVALID',
            site=self.site
        )

    def __repr__(self):
        return 'Signature: {0}'.format(self)
