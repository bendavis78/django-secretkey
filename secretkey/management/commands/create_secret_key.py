import os
import sys
from optparse import make_option

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.six.moves import input

from secretkey import utils
from secretkey.models import Signature


class Command(BaseCommand):
    help = ("Generates a randomized secret key and places it in "
            "the SECRET_KEY_FILE.\n\nThis command will also create a stored "
            "signature to help prevent future changes in the SECRET_KEY")
    option_list = BaseCommand.option_list + (
        make_option('-l', '--length', action='store', dest='key_length',
                    default='64', help='The key length in bytes'),
        make_option('--force', action='store_true',
                    dest='force', default=False, help=(
                        "Replaces the current signature used to prevent "
                        "accidental changes in the secret key."))
    )
    can_import_settings = True
    requires_system_checks = False

    def handle(self, **opts):
        try:
            key_length = int(opts['key_length'])
        except TypeError:
            raise CommandError("Invalid key length '{0}'".format(key_length))

        from django.conf import settings, ImproperlyConfigured
        if not settings.SECRET_KEY_FILE:
            raise ImproperlyConfigured(
                "The SECRET_KEY_FILE setting must not be empty.")

        if os.path.exists(settings.SECRET_KEY_FILE):
            # we don't want to accentally overwrite an existing secret key
            raise CommandError("The SECRET_KEY_FILE '{}' already exists."
                               .format(settings.SECRET_KEY_FILE))

        self.verify(opts)
        utils.create_secret_key_file(settings.SECRET_KEY_FILE,
                                     key_length=key_length)
        self.update_signature(opts)
        self.stdout.write(self.style.NOTICE(
            "Successfully create secret key in '{}'\n"
            .format(settings.SECRET_KEY_FILE)))

    def verify(self, opts):
        # don't do any db operations if this app hasn't been migrated yet
        if not Signature.objects.db_ready():
            return

        current = Signature.objects.get_current()
        if current and not opts['force']:
            raise CommandError(
                "An existing signature was found: \{0}\.\n If you are sure "
                "you want to create a new secret key, run this command with "
                "the --force option. ".format(current))

        if current:
            msg = ("{WARNING}\nThis will overwrite the current signature:\n\n "
                   "..{current}\n\nThe signature is used to prevent "
                   "accidental changes to the secret key. Changing the secret "
                   "key may result in data that is no longer usable. Are you "
                   "sure sure you want to do this?\n\nType 'yes' to continue: "
                   .format(WARNING=self.style.ERROR("WARNING:"),
                           current=current))

            if input(msg) != 'yes':
                self.stdout.write(self.style.NOTICE("Command aborted."))
                sys.exit(0)

    @transaction.atomic
    def update_signature(self, opts):
        # don't do any db operations if this app hasn't been migrated yet
        if not Signature.objects.db_ready():
            return
        signature = Signature.objects.create_signature(force=opts['force'])
        sys.stdout.write("\nCreated signature: {0}\n".format(signature))
