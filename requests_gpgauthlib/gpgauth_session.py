# requests_gpgauthlib -- A GPGAuth python-requests Authentication lib
# Copyright (C) 2018 Didier Raboud <odyx@liip.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

import logging
import os
import re

from gnupg import GPG
from requests import Session
from tempfile import TemporaryDirectory
from urllib.parse import unquote_plus
from uuid import uuid4

from .exceptions import GPGAuthException, GPGAuthStage0Exception

logger = logging.getLogger(__name__)


class GPGAuthSession(Session):
    """GPGAuth extension to :class:`requests.Session`.
    """
    VERIFY_URI = '/verify.json'
    LOGIN_URI = '/login.json'

    # This is passbolt_api's version
    GPGAUTH_SUPPORTED_VERSION = '1.3.0'

    def __init__(self, auth_url, server_fingerprint, amnesic_gpg=False, **kwargs):
        """Construct a new GPGAuth client session.
        :param auth_url: URL to the GPGAuth endpoint (…/auth/)
        :param server_fingerprint: Full PGP fingerprint of the server
        :param amnesic_gpg: Boolean; Use a temporary GnuPG Home directory for every run
        :param kwargs: Arguments to pass to the Session constructor.
        """
        self.auth_url = re.sub(r'/$', '', auth_url)  # Drop the trailing slash
        self._server_fingerprint = server_fingerprint
        self._amnesic_gpg = amnesic_gpg
        super(GPGAuthSession, self).__init__(**kwargs)

    @property
    def _nonce0(self):
        try:
            return self.__nonce0
        except AttributeError:
            pass
        # This format is stolen from
        # https://github.com/passbolt/passbolt_cli/blob/master/app/models/gpgAuthToken.js
        self.__nonce0 = 'gpgauthv%s|36|' % self.GPGAUTH_SUPPORTED_VERSION
        self.__nonce0 += str(uuid4())
        self.__nonce0 += '|gpgauthv%s' % self.GPGAUTH_SUPPORTED_VERSION
        return self.__nonce0

    @property
    def workdir(self):
        try:
            return self._workdir
        except AttributeError:
            pass

        # Setup our home
        _userhome = os.environ.get('HOME')
        if not _userhome:
            _userhome = '/tmp/requests_gpgauthlib'
            try:
                os.makedirs(_userhome)
            except (OSError, IOError):
                _userhome = os.getcwd()
        self._workdir = os.path.join(os.path.join(_userhome, '.config'), 'requests_gpgauthlib')
        try:
            os.makedirs(self._workdir, exist_ok=True)
        except (OSError, IOError):
            pass
        return self._workdir

    @property
    def gpg(self):
        try:
            return self._gpg
        except AttributeError:
            pass

        # Instantiate GnuPG in a specific directory
        _gpghomedirname = os.path.join(self.workdir, '.gnupg')
        if self._amnesic_gpg:
            # Instantiate this as a class attribute to let it be destroyed automagically
            self._temporarygpghomedir = TemporaryDirectory(prefix='requests_gpgauthlib-')
            _gpghomedirname = self._temporarygpghomedir.name
        # Instantiate the GnuPG process
        self._gpg = GPG(homedir=_gpghomedirname)
        return self._gpg

    @property
    def gpgauth_version_is_supported(self):
        try:
            return self._gpgauth_version_is_supported is True
        except AttributeError:
            pass

        # We don't know, let's verify
        r = self.head(self.auth_url)
        if 'X-GPGAuth-Version' not in r.headers:
            logger.debug(r.headers)
            raise GPGAuthException(
                "GPGAuth support not announced by %s" % self.auth_url
            )
        if r.headers['X-GPGAuth-Version'] != self.GPGAUTH_SUPPORTED_VERSION:
            raise GPGAuthException(
                "GPGAuth Version not supported (%s != %s)" % (
                    r.headers['X-GPGAuth-Version'],
                    GPGAUTH_SUPPORTED_VERSION
                 )
            )
        self._gpgauth_version_is_supported = True
        logger.info('gpgauth_version_is_supported(): OK')
        return True

    @property
    def server_fingerprint(self):
        if hasattr(self, '_server_key'):
            return self._server_fingerprint

        if not self.gpgauth_version_is_supported:
            return False

        # Try to get them from GPG
        server_key = self.gpg.export_keys([self._server_fingerprint], secret=False, subkeys=False)
        if 'BEGIN PGP PUBLIC KEY BLOCK' in server_key:
            self._server_key = server_key
            return self._server_fingerprint

        # Try to get it from the server
        r = self.get(self.auth_url + self.VERIFY_URI)
        if r.json()['body']['fingerprint'] != self._server_fingerprint:
            raise GPGAuthException(
                "Hoped server fingerprint %s doesn't match the server's %s" %
                (self._server_fingerprint, r.json()['body']['fingerprint'])
            )
        _server_key = r.json()['body']['keydata']
        import_result = self.gpg.import_keys(_server_key)
        if self._server_fingerprint not in import_result.fingerprints:
            raise GPGAuthException(
                "Hoped server fingerprint %s doesn't match the server key." %
                self._server_fingerprint
            )
        logger.info('server_fingerprint(): 0x%s '
                    'imported successfully' % self._server_fingerprint)
        self._server_key = _server_key
        return self._server_fingerprint

    @property
    def user_fingerprint(self):
        try:
            return self._user_fingerprint
        except AttributeError:
            pass

        # Try to get them from GPG
        secret_keys = self.gpg.list_keys(secret=True)
        if not secret_keys:
            raise GPGAuthException('No user fingerprint was loaded, you need to call import_user_private_key_from_file()')
        # Assume the main key is the first
        self._user_fingerprint = secret_keys.fingerprints[0]
        return self._user_fingerprint

    def import_user_private_key_from_file(self, user_private_key_file):
        # Import the user private key
        with open(user_private_key_file, 'r') as key:
            logger.info('Importing the user private key; password prompt expected')
            import_result = self.gpg.import_keys(key.read())
            if len(import_result.fingerprints) < 1:
                raise GPGAuthException('No key could be imported')
            else:
                [
                    logger.info('GPG key 0x%s successfully imported' % key)
                    for key in import_result.fingerprints
                ]
                self._user_fingerprint = import_result.fingerprints.pop()
        return self._user_fingerprint

    def server_identity_verified(self):
        """ GPGAuth stage0 """
        try:
            return self._server_identity_verified
        except AttributeError:
            pass

        # Encrypt a uuid token for the server
        server_verify_token = self.gpg.encrypt(self._nonce0,
                                               self.server_fingerprint)
        if not server_verify_token.ok:
            raise GPGAuthStage0Exception(
                'Encryption of the nonce0 (%s) '
                'to the server fingerprint (%s) failed.' %
                (self._nonce0, self.server_fingerprint)
            )

        r = self.post(
            self.auth_url + self.VERIFY_URI,
            json={'gpg_auth': {
                'keyid': self.user_fingerprint,
                'server_verify_token': str(server_verify_token)
                }
            },
        )

        validation_errors = []
        if r.headers['X-GPGAuth-Authenticated'] != 'false':
            validation_errors.append(
                GPGAuthStage0Exception(
                    'X-GPGAuth-Authenticated should be set to false'))
        if r.headers['X-GPGAuth-Progress'] != 'stage0':
            validation_errors.append(
                GPGAuthStage0Exception(
                    'X-GPGAuth-Progress should be set to stage0'))
        if 'X-GPGAuth-User-Auth-Token' in r.headers:
            validation_errors.append(
                GPGAuthStage0Exception(
                    'X-GPGAuth-User-Auth-Token should not be set'))
        if 'X-GPGAuth-Verify-Response' not in r.headers:
            validation_errors.append(
                GPGAuthStage0Exception(
                    'X-GPGAuth-Verify-Response should be set'))
        if 'X-GPGAuth-Refer' in r.headers:
            validation_errors.append(
                GPGAuthStage0Exception(
                    'X-GPGAuth-Refer should not be set'))

        if validation_errors:
            logger.warning(r.headers)
            raise validation_errors.pop()

        if r.headers['X-GPGAuth-Verify-Response'] != self._nonce0:
            raise GPGAuthStage0Exception(
                'The server decrypted something different than what we sent '
                '(%s <> %s)' %
                (r.headers['X-GPGAuth-Verify-Response'], self._nonce0))
        self._server_identity_verified = True
        logger.info('server_identity_verified(): OK')

    def logged_in(self):
        """ GPGAuth Stage1 """
        """ Get and decrypt a verification given by the server """
        try:
            self._user_auth_token
            return
        except AttributeError:
            pass

        # Prerequisite
        self.server_identity_verified()

        r = self.post(
            self.auth_url + self.LOGIN_URI,
            json={'gpg_auth': {'keyid': self.user_fingerprint}}
        )

        validation_errors = []
        if r.headers['X-GPGAuth-Authenticated'] != 'false':
            validation_errors.append(
                GPGAuthStage1Exception(
                    'X-GPGAuth-Authenticated should be set to false'))
        if r.headers['X-GPGAuth-Progress'] != 'stage1':
            validation_errors.append(
                GPGAuthStage1Exception(
                    'X-GPGAuth-Progress should be set to stage1'))
        if 'X-GPGAuth-User-Auth-Token' not in r.headers:
            validation_errors.append(
                GPGAuthStage1Exception(
                    'X-GPGAuth-User-Auth-Token should be set'))
        if 'X-GPGAuth-Verify-Response' in r.headers:
            validation_errors.append(
                GPGAuthStage1Exception(
                    'X-GPGAuth-Verify-Response should not be set'))
        if 'X-GPGAuth-Refer' in r.headers:
            validation_errors.append(
                GPGAuthStage1Exception(
                    'X-GPGAuth-Refer should not be set'))

        if validation_errors:
            logger.warning(r.headers)
            raise validation_errors.pop()

        # Get the encrypted User Auth Token
        encrypted_user_auth_token = unquote_plus(
            r.headers['X-GPGAuth-User-Auth-Token']
            .replace('\\\\', '\\')
        ).replace('\\ ', ' ')
        logger.info('Decrypting the user authentication token; '
                    'password prompt expected')
        self._user_auth_token = str(
            self.gpg.decrypt(encrypted_user_auth_token, always_trust=True)
        )
        logger.info('logged_in(): OK')

    # GPGAuth stages in numerical form
    stage0 = server_identity_verified
    stage1 = logged_in
