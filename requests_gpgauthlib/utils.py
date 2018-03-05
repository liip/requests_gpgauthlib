import logging
import os
from tempfile import TemporaryDirectory

from gnupg import GPG

from .exceptions import GPGAuthKeyImportError

logger = logging.getLogger(__name__)


def get_workdir():
    _userhome = os.environ.get('HOME')
    if not _userhome:
        _userhome = '/tmp/requests_gpgauthlib'
        try:
            os.makedirs(_userhome, exist_ok=True)
            logger.warn('get_workdir: HOME undefined, using {}'.format(_userhome))
        except (OSError, IOError):
            _userhome = os.getcwd()
            logger.warn('get_workdir: HOME undefined and /tmp unwriteable, using {}'.format(_userhome))
    workdir = os.path.join(os.path.join(_userhome, '.config'), 'requests_gpgauthlib')

    try:
        os.makedirs(workdir, exist_ok=True)
    except (OSError, IOError):
        pass

    return workdir


def get_temporary_workdir():
    return TemporaryDirectory(prefix='requests_gpgauthlib-')


def create_gpg(workdir):
    gpg = GPG(gnupghome=os.path.join(workdir, '.gnupg'))
    gpg.encoding = 'utf-8'
    return gpg


def import_user_private_key_from_file(gpg, user_private_key_file):
    with open(user_private_key_file, 'r') as key:
        logger.info('Importing the user private key; password prompt expected')
        import_result = gpg.import_keys(key.read())
        if len(import_result.fingerprints) < 1:
            raise GPGAuthKeyImportError('No key could be imported')
        else:
            [
                logger.info('GPG key 0x%s successfully imported' % key)
                for key in import_result.fingerprints
            ]
            user_fingerprint = import_result.fingerprints.pop()

    return user_fingerprint
