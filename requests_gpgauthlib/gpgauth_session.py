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
from http.cookiejar import MozillaCookieJar
from urllib.parse import unquote_plus
from uuid import uuid4

from requests import Session

from .exceptions import (GPGAuthException, GPGAuthNoSecretKeyError, GPGAuthStage0Exception, GPGAuthStage1Exception,
                         GPGAuthStage2Exception)
from .utils import get_workdir

logger = logging.getLogger(__name__)


class GPGAuthSession(Session):
    """GPGAuth extension to :class:`requests.Session`.
    """
    VERIFY_URI = '/verify.json'
    LOGIN_URI = '/login.json'
    CHECKSESSION_URI = '/checkSession.json'

    # This is passbolt_api's version
    GPGAUTH_SUPPORTED_VERSION = '1.3.0'

    def __init__(self, gpg, server_url, auth_uri, server_fingerprint, **kwargs):
        """Construct a new GPGAuth client session.
        :param gpg: GPG object to handle crypto stuff
        :param server_url: URL to the server, eg. https://gpg.example.com/
        :param auth_uri: URI to the GPGAuth endpoint (…/auth/), used as a prefix for all auth URIs
        :param server_fingerprint: Full PGP fingerprint of the server
        :param server_url: Full PGP fingerprint of the server
        :param kwargs: Arguments to pass to the Session constructor.
        """
        super(GPGAuthSession, self).__init__(**kwargs)

        self.server_url = server_url.rstrip('/')
        self.auth_uri = auth_uri.rstrip('/')
        self.gpg = gpg
        self._server_fingerprint = server_fingerprint

        self._cookie_filename = os.path.join(get_workdir(), 'gpgauth_session_cookies')
        self.cookies = MozillaCookieJar(self._cookie_filename)
        try:
            self.cookies.load()
        except FileNotFoundError:
            pass

    def build_absolute_uri(self, uri):
        """
        Return the given URI in an absolute form with the server name, eg. https://secure.example.com/uri/.
        """
        return self.server_url + uri

    def build_absolute_auth_uri(self, uri):
        """
        Return the given URI in an absolute form with the server name and the auth URI prefix, eg.
        https://secure.example.com/auth/uri/.
        """
        return self.build_absolute_uri(self.auth_uri + uri)

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
    def gpgauth_version_is_supported(self):
        try:
            return self._gpgauth_version_is_supported is True
        except AttributeError:
            pass

        # We don't know, let's verify
        r = self.get(self.build_absolute_auth_uri(self.VERIFY_URI))
        if 'X-GPGAuth-Version' not in r.headers:
            logger.debug(r.headers)
            raise GPGAuthException(
                "GPGAuth support not announced by %s" % self.auth_uri + self.VERIFY_URI
            )
        if r.headers['X-GPGAuth-Version'] != self.GPGAUTH_SUPPORTED_VERSION:
            raise GPGAuthException(
                "GPGAuth Version not supported (%s != %s)" % (
                    r.headers['X-GPGAuth-Version'],
                    self.GPGAUTH_SUPPORTED_VERSION
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
        server_key = self.gpg.export_keys([self._server_fingerprint], secret=False)
        if 'BEGIN PGP PUBLIC KEY BLOCK' in server_key:
            self._server_key = server_key
            return self._server_fingerprint

        # Try to get it from the server
        r = self.get(self.build_absolute_auth_uri(self.VERIFY_URI))
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
            raise GPGAuthNoSecretKeyError(
                'No user fingerprint was loaded! You need to call import_user_private_key_from_file() first!'
            )
        # Assume the main key is the first
        self._user_fingerprint = secret_keys.fingerprints[0]
        return self._user_fingerprint

    @property
    def user_auth_token(self):
        try:
            return self._user_auth_token
        except AttributeError:
            pass
        self.logged_in()
        return self._user_auth_token

    def server_identity_verified(self):
        """ GPGAuth stage0 """
        try:
            return self._server_identity_verified
        except AttributeError:
            pass

        # Encrypt a uuid token for the server
        server_verify_token = self.gpg.encrypt(self._nonce0,
                                               self.server_fingerprint, always_trust=True)
        if not server_verify_token.ok:
            raise GPGAuthStage0Exception(
                'Encryption of the nonce0 (%s) '
                'to the server fingerprint (%s) failed.' %
                (self._nonce0, self.server_fingerprint)
            )

        r = self.post(
            self.build_absolute_auth_uri(self.VERIFY_URI),
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
            logger.debug(r.headers)
            if 'X-GPGAuth-Debug' in r.headers:
                raise GPGAuthStage0Exception('The server indicated "%s"' % r.headers['X-GPGAuth-Debug'])
            else:
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
            self.build_absolute_auth_uri(self.LOGIN_URI),
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
            logger.debug(r.headers)
            if 'X-GPGAuth-Debug' in r.headers:
                raise GPGAuthStage1Exception('The server indicated "%s"' % r.headers['X-GPGAuth-Debug'])
            else:
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

    def authenticated_with_token(self):
        """ GPGAuth Stage 2 """
        """ Send back the token to the server to get auth cookie """

        r = self.post(self.build_absolute_auth_uri(self.LOGIN_URI),
                      json={'gpg_auth': {
                          'keyid': self.user_fingerprint,
                          'user_token_result': self.user_auth_token,
                          }}
                      )
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
            logger.debug(r.headers)
            if 'X-GPGAuth-Debug' in r.headers:
                raise GPGAuthStage2Exception('The server indicated "%s"' % r.headers['X-GPGAuth-Debug'])
            else:
                raise validation_errors.pop()
        self.cookies.save()
        logger.info('authenticated_with_token(): OK')

    def is_authenticated(self):
        r = self.get(self.build_absolute_auth_uri(self.CHECKSESSION_URI))
        return r.status_code not in [401, 403]

    def authenticate(self):
        if self.is_authenticated():
            return
        self.authenticated_with_token()

    # GPGAuth stages in numerical form
    stage0 = server_identity_verified
    stage1 = logged_in
    stage2 = authenticated_with_token
