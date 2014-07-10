import hashlib
import os
import string
import time
import uuid

import lockfile
from django.utils import crypto
from django.utils.six.moves import range


def generate_secret_key(length=64):
    """
    Generates a secure randomized key with the given length.

    The quality of randomness depends on operating system support,
    see http://docs.python.org/library/random.html#random.SystemRandom.
    """
    random = crypto.random
    if not crypto.using_sysrandom:
        # Python's PRNG (Mersenne Twister) is completely deterministic, so we
        # need to re-seed it using a harder to guess value. This is also done
        # by django's get_random_string() function, except that it salts the
        # hash using SECRET_KEY. And since of course we can't use that, we'll
        # use uuid4() in its place.
        random.seed(
            hashlib.sha512(''.join([
                random.getstate(),
                time.time().encode('utf-8'),
                uuid.uuid4()
            ])).digest()
        )
    rand = random.random
    chars = string.printable.strip()
    return ''.join(chars[int(rand() * len(chars))] for i in range(0, length))


def create_secret_key_file(key_file, key_length=64):
    """
    Generates a secret key and writes it to `key_file` in a manner that is
    secure and multiprocess-safe.
    """
    with lockfile.FileLock(key_file):
        if not os.path.exists(key_file):
            key = generate_secret_key(key_length)
            # create the file with secure permissions (0600)
            old_umask = os.umask(0o177)
            with open(key_file, 'w') as f:
                f.write(key)
            os.umask(old_umask)
