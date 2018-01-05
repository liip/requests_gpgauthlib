# python-gpgauth -- A GPGAuth Client in Python
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

import requests
import logging
import re
import uuid

from gnupg import GPG, _parsers as GPG_parsers
from urllib.parse import unquote_plus

from tempfile import TemporaryDirectory

from .exceptions import (
        GPGAuthException, GPGAuthStage0Exception, GPGAuthStage1Exception,
        GPGAuthStage2Exception
        )

# This is passbolt_api's version
GPGAUTH_SUPPORTED_VERSION = '1.3.0'

logger = logging.getLogger(__name__)

# Hide various error messages
# Addresses https://github.com/isislovecruft/python-gnupg/issues/207 at least
GPG_parsers.Verify.TRUST_LEVELS["ENCRYPTION_COMPLIANCE_MODE"] = 23
GPG_parsers.Verify.TRUST_LEVELS["DECRYPTION_KEY"] = 24
GPG_parsers.Verify.TRUST_LEVELS["VERIFICATION_COMPLIANCE_MODE"] = 25


class GPGAuth:
    """ GPGAuth client Class """

    def __init__(self, server_url, server_fingerprint, user_private_key_file,
                 http_username=None, http_password=None):
        # Strip trailing slash
        self.server_url = re.sub(r'/$', '', server_url)
        self.serverkey_imported = False
        self._server_fingerprint = server_fingerprint
        self._requests = requests.Session()
        if http_username and http_password:
            self._requests.auth = \
                    requests.auth.HTTPBasicAuth(http_username, http_password)
        with open(user_private_key_file, 'r') as key:
            logger.info(
                    'Importing the user private key; password prompt expected'
                    )
            print('python-gpgauth:'
                  ' Importing the user private key; password prompt expected')
            import_result = self.gpg.import_keys(key.read())
            if len(import_result.fingerprints) < 1:
                raise GPGAuthException('No key could be imported')
            else:
                [
                    logger.info('GPG key 0x%s successfully imported' % key)
                    for key in import_result.fingerprints
                ]
                self.user_fingerprint = import_result.fingerprints.pop()

    @property
    def gpg(self):
        try:
            self._gpg
        except AttributeError:
            # Instantiate GnuPG in a specific directory
            self._gpg = GPG(
                    homedir=TemporaryDirectory(
                      prefix='python-gpgauth-cli-'
                    ).name,
                    use_agent=True,
                    )
            return self._gpg

    @property
    def requests(self):
        """ Return a python-requests Object       """
        """ with an authenticated GPGAuth context """
        if not hasattr(self, '_authenticated_url'):
            self.authenticate_with_token()
        return self._requests

    @property
    def _nonce0(self):
        try:
            self.__nonce0
        except AttributeError:
            # This format is stolen from
            # https://github.com/passbolt/passbolt_cli/blob/master/app/models/gpgAuthToken.js
            self.__nonce0 = 'gpgauthv1.3.0|36|'
            self.__nonce0 += str(uuid.uuid4())
            self.__nonce0 += '|gpgauthv1.3.0'
        return self.__nonce0

    @property
    def user_auth_token(self):
        try:
            self._user_auth_token
        except AttributeError:
            self.login()
        return self._user_auth_token

    @property
    def login_url(self):
        if not hasattr(self, '_login_url'):
            self.verify_gpgauth_version()
        return self._login_url

    def verify_gpgauth_version(self):
        if hasattr(self, 'gpgauth_version_ok'):
            return self.gpgauth_version_ok is True

        r = self._requests.head(self.server_url + '/auth/')
        if 'X-GPGAuth-Version' not in r.headers:
            raise GPGAuthException(
                "GPGAuth support not announced by %s" % self.server_url
            )
        if r.headers['X-GPGAuth-Version'] != GPGAUTH_SUPPORTED_VERSION:
            raise GPGAuthException(
                "GPGAuth Version not supported (%s != %s)" % (
                    r.headers['X-GPGAuth-Version'],
                    GPGAUTH_SUPPORTED_VERSION
                 )
            )
        self.gpgauth_version_ok = True

        # We know the URLs from the server are broken (no .json postfix),
        # use our own.
        self.verify_url = self.server_url + '/auth/verify.json'
        self._login_url = self.server_url + '/auth/login.json'
        logger.info('verify_gpgauth_version(): OK')

    @property
    def server_fingerprint(self):
        if self.serverkey_imported:
            return self._server_fingerprint

        # Prerequisite
        self.verify_gpgauth_version()

        r = self._requests.get(self.verify_url)
        if r.json()['body']['fingerprint'] != self._server_fingerprint:
            raise GPGAuthException(
                "Hoped server fingerprint %s doesn't match the server's %s" %
                (self._server_fingerprint, r.json()['body']['fingerprint'])
            )
        import_result = self.gpg.import_keys(r.json()['body']['keydata'])
        if self._server_fingerprint not in import_result.fingerprints:
            raise GPGAuthException(
                "Hoped server fingerprint %s doesn't match the server key." %
                self._server_fingerprint
            )
        logger.info('server_fingerprint(): 0x%s '
                    'imported successfully' % self._server_fingerprint)
        self.serverkey_imported = True

        return self._server_fingerprint

    def verify_server_identity(self):
        """ GPGAuth stage0 """
        if hasattr(self, '_server_identity_verified'):
            return

        # Prerequisite
        self.verify_gpgauth_version()

        # Encrypt a uuid token for the server
        server_verify_token = self.gpg.encrypt(self._nonce0,
                                               self.server_fingerprint)
        if not server_verify_token.ok:
            raise GPGAuthStage0Exception(
                'Encryption of the nonce0 (%s) '
                'to the server fingerprint (%s) failed.' %
                (self._nonce0, self.server_fingerprint)
            )

        r = self._requests.post(
            self.verify_url,
            json={'gpg_auth': {
                'keyid': self.user_fingerprint,
                'server_verify_token': str(server_verify_token)
                }
            }
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
        logger.info('verify_server_identity(): OK')

    def login(self):
        """ GPGAuth Stage1 - get and decrypt a verification given by the """
        """ server """
        if hasattr(self, '_user_auth_token'):
            return

        # Prerequisite
        self.verify_server_identity()

        r = self._requests.post(
            self.login_url,
            json={'gpg_auth': {'keyid': self.user_fingerprint}})

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
            .replace('\\ ', ' ')
        )
        logger.info('Decrypting the user authentication token; '
                    'password prompt expected')
        print('python-gpgauth: Decrypting the user authentication token; '
              'password prompt expected')
        self._user_auth_token = str(
            self.gpg.decrypt(encrypted_user_auth_token, always_trust=True)
        )
        logger.info('login(): OK')

    def authenticate_with_token(self):
        """ GPGAuth Stage 2 """
        """ Send back the token to the server to get auth cookie """

        r = self._requests.post(self.login_url, json={'gpg_auth': {
            'keyid': self.user_fingerprint,
            'user_token_result': self.user_auth_token,
            }})

        validation_errors = []
        if r.headers['X-GPGAuth-Authenticated'] != 'true':
            validation_errors.append(
                GPGAuthStage2Exception(
                    'X-GPGAuth-Authenticated should be set to true'))
        if r.headers['X-GPGAuth-Progress'] != 'complete':
            validation_errors.append(
                GPGAuthStage2Exception(
                    'X-GPGAuth-Progress should be set to complete'))
        if 'X-GPGAuth-User-Auth-Token' in r.headers:
            validation_errors.append(
                GPGAuthStage2Exception(
                    'X-GPGAuth-User-Auth-Token should not be set'))
        if 'X-GPGAuth-Verify-Response' in r.headers:
            validation_errors.append(
                GPGAuthStage2Exception(
                    'X-GPGAuth-Verify-Response should not be set'))
        if 'X-GPGAuth-Refer' not in r.headers:
            validation_errors.append(
                GPGAuthStage2Exception(
                    'X-GPGAuth-Refer should be set'))

        if validation_errors:
            logger.warning(r.headers)
            raise validation_errors.pop()

        # Get the encrypted User Auth Token
        self._authenticated_url = (
            self.server_url + r.headers['X-GPGAuth-Refer']
        )
        logger.info('authenticate_with_token(): OK — '
                    'Now go to %s' % self._authenticated_url)

    # GPGAuth stages in numerical form
    stage0 = verify_server_identity
    stage1 = login
    stage2 = authenticate_with_token
