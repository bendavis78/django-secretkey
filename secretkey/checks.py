# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

from django.conf import settings
from django.core import checks

from secretkey.models import Signature


@checks.register('security', 'secretkey')
def check_secret_key_file(*args, **kwargs):
    errors = []

    # Check that the setting is not empty
    if not settings.SECRET_KEY_FILE:
        errors.append(checks.Error(
            "The SECRET_KEY_FILE setting must not be empty.",
            obj=settings.SETTINGS_MODULE,
            id='secretkey.E001'))

    # Check that the key file exists
    if not os.path.exists(settings.SECRET_KEY_FILE):
        errors.append(checks.Error(
            "The secret key file '{}' does not exist."
            .format(settings.SECRET_KEY_FILE),
            hint=("Run the 'create_secret_key' management command to "
                  "create it."),
            obj=settings.SETTINGS_MODULE,
            id='secretkey.E002'))

        # remaining checks require that the file exists
        return errors

    filename = os.path.basename(settings.SECRET_KEY_FILE)
    # Check that it has secure permissions
    if oct(os.stat(settings.SECRET_KEY_FILE).st_mode & 0o777) != '0600':
        errors.append(checks.Error(
            "The secret key file has insecure permisisons.",
            hint=("Try running: chmod 0600 {0}"
                  .format(settings.SECRET_KEY_FILE)),
            obj=filename,
            id='secretkey.E003'))

    # The default length for SECRET_KEY has historically been 50
    key = open(settings.SECRET_KEY_FILE, 'r').read()
    length = len(key)
    if length <= 50:
        errors.append(checks.Warning(
            "The secret key file is bytes, which is shorter than the "
            "recommended key length of 50.",
            obj=settings,
            id='secretkey.W004'))

    # If the db has not been migrated yet, skip the rest of the checks
    if not Signature.objects.db_ready():
        return errors

    # Make sure the current signature is still valid
    current = Signature.objects.get_current()
    if not current:
        # This can happen if the SECRET_KEY_FILE was created manually
        errors.append(checks.Error(
            "The current site does not yet have a stored signature, which is "
            "used  prevent accidental changes to the secret key. ",
            hint="Run the 'update_signature' management command to create a "
                 "new signature.",
            obj=Signature,
            id='secretkey.E005'))

    if current and not current.is_valid():
        errors.append(checks.Error(
            "It appears as if your SECRET_KEY has changed. The current key "
            "is:\n\n  {0}\n\nThe key is invalid, which may be due to an "
            "unintential change in the SECRET_KEY_FILE. Changing the secret "
            "key will result in the loss of any data that has been "
            "cryptographically signed by a previous key. If you cannot "
            "restore the previous key, you can create a create a new "
            "signature using the 'update_signature' management command. "
            .format(current),
            obj=Signature,
            id='secretkey.E006'))

    return errors
