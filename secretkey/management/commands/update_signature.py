import sys
from optparse import make_option

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.six.moves import input

from secretkey import checks
from secretkey.models import Signature


class Command(BaseCommand):
    help = ("Updates the stored signature, used to prevent accidental "
            "changes to the secret key.")
    option_list = BaseCommand.option_list + (
        make_option('--force', action='store_true',
                    dest='force', default=False, help=(
                        "Replaces the current signature used to prevent "
                        "accidental changes in the secret key.")),
    )
    can_import_settings = True
    requires_system_checks = False

    @transaction.atomic
    def handle(self, **opts):
        # run certain checks manually
        errors = checks.check_secret_key_file()
        fail = {'secretkey.' + e for e in ('E001', 'E002', 'E003')}
        if set(e.id for e in errors) & fail:
            raise CommandError(errors[0].msg)

        if not Signature.objects.db_ready():
            raise CommandError(
                "The database used to store the signature is not ready. You "
                "may need to run 'manage.py migrate' first.")

        force = False
        current = Signature.objects.get_current()
        if current:
            if current.is_valid():
                raise CommandError("The current signature is valid and does "
                                   "not need updating:\n\n  {0}\n\n"
                                   .format(current))

            msg = ("{WARNING}\nThis will overwrite the current signature: "
                   "\"{current}\"\n\n"
                   "The signature is used to prevent accidental changes "
                   "to the secret key. Are you sure you want to do this?\n\n"
                   "Type 'yes' to continue: "
                   .format(WARNING=self.style.ERROR('WARNING:'),
                           current=current))

            if input(msg) != 'yes':
                self.stdout.write(self.style.NOTICE("Command aborted."))
                sys.exit(0)

            force = True

        signature = Signature.objects.create_signature(force=force)
        sys.stdout.write("Created signature: {0}\n".format(signature))
