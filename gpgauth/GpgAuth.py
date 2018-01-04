# -*- coding: utf-8 -*-
#
# python-gpgauth -- A GPGAuth Client in Python
# Copyright (C) 2017 Didier Raboud <odyx@liip.ch>
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

from tempfile import TemporaryDirectory

from .exceptions import GPGAuthException

# This is passbolt_api's version
GPGAUTH_SUPPORTED_VERSION = '1.3.0'

logger = logging.getLogger(__name__)

# Bugfix for https://github.com/isislovecruft/python-gnupg/issues/207
GPG_parsers.Verify.TRUST_LEVELS["ENCRYPTION_COMPLIANCE_MODE"] = 23

class GPGAuth:
    """ GPGAuth client Class """

    def __init__(self, server_url, server_fingerprint, user_private_key_file, http_username=None, http_password=None):
        # Strip trailing slashes
        self.server_url = re.sub(r'/$', '', server_url)
        self.serverkey_imported = False
        self._server_fingerprint = server_fingerprint
        self.requests = requests.Session()
        if http_username and http_password:
           self.requests.auth = requests.auth.HTTPBasicAuth(http_username, http_password)
        with open(user_private_key_file, 'r') as key:
          logger.info('Importing the user private key file; password prompt expected')
          import_result = self.gpg.import_keys(key.read())
          if len(import_result.fingerprints) < 1:
            raise GPGAuthException('No key could be imported')
          else:
            [logger.info('GPG key 0x%s successfully imported' % key) for key in import_result.fingerprints]
            self.user_fingerprint = import_result.fingerprints.pop()

    @property
    def gpg(self):
        try:
            self._gpg
        except AttributeError:
            # Instantiate GnuPG in a specific directory
            self._gpg = GPG(homedir=TemporaryDirectory(prefix='gpgauth').name)
        return self._gpg


    @property
    def _nonce0(self):
      try:
          self.__nonce0
      except AttributeError:
          # This format is stolen from https://github.com/passbolt/passbolt_cli/blob/master/app/models/gpgAuthToken.js
          self.__nonce0  = 'gpgauthv1.3.0|36|';
          self.__nonce0 += str(uuid.uuid4());
          self.__nonce0 += '|gpgauthv1.3.0';
      return self.__nonce0


    def verify_gpgauth_version(self):
        if hasattr(self, 'gpgauth_version_ok'):
            return self.gpgauth_version_ok == True

        r = self.requests.head(self.server_url + '/auth/')
        if 'X-GPGAuth-Version' not in r.headers:
            raise GPGAuthException("GPGAuth support not announced by %s" % self.server_url)
        if r.headers['X-GPGAuth-Version'] != GPGAUTH_SUPPORTED_VERSION:
            raise GPGAuthException("GPGAuth Version not supported (%s != %s)" % (r.headers['X-GPGAuth-Version'], GPGAUTH_SUPPORTED_VERSION))
        self.gpgauth_version_ok = True

        # Take the information from the server if they give them
        self.verify_url = self.server_url + '/auth/verify.json'
        # This is broken. Without the .json postfix, it breaks
        #if 'X-GPGAuth-Verify-Url' in r.headers:
            #self.verify_url = self.server_url + r.headers['X-GPGAuth-Verify-Url']
        logger.info('verify_gpgauth_version(): OK')

    @property
    def server_fingerprint(self):
        if self.serverkey_imported:
            return self._server_fingerprint

        # Prerequisite
        self.verify_gpgauth_version()

        r = self.requests.get(self.verify_url)
        if r.json()['body']['fingerprint'] != self._server_fingerprint:
            raise GPGAuthException("Hoped server fingerprint %s doesn't match the server's %s." % (self._server_fingerprint, r.json()['body']['fingerprint']))
        import_result = self.gpg.import_keys(r.json()['body']['keydata'])
        if self._server_fingerprint not in import_result.fingerprints:
            raise GPGAuthException("Hoped server fingerprint %s doesn't match the server key." % self._server_fingerprint)
        logger.info('server_fingerprint(): 0x%s imported successfully' % self._server_fingerprint)
        self.serverkey_imported = True

        return self._server_fingerprint

    def verify_server_identity(self):
        """ GPGAuth stage0 """
        self.verify_gpgauth_version()
        # Encrypt a uuid token for the server
        server_verify_token = self.gpg.encrypt(self._nonce0, self.server_fingerprint)
        if not server_verify_token.ok:
            raise GPGAuthException('Encryption of the nonce0 (%s) to the server fingerprint (%s) failed.' % (self._nonce0, self.server_fingerprint))

        r = self.requests.post(self.verify_url,
                               json = {
                                   'gpg_auth': {
                                       'keyid': self.user_fingerprint,
                                       'server_verify_token': str(server_verify_token)
                                    }
                                })

        validation_errors = []
        if r.headers['X-GPGAuth-Authenticated'] != 'false':
            validation_errors.append(GPGAuthException('X-GPGAuth-Authenticated should be set to false during the verify stage'))
        if r.headers['X-GPGAuth-Progress'] != 'stage0':
            validation_errors.append(GPGAuthException('X-GPGAuth-Progress should be set to stage0 during the verify stage'))
        if 'X-GPGAuth-User-Auth-Token' in r.headers:
            validation_errors.append(GPGAuthException('X-GPGAuth-User-Auth-Token should not be set during the verify stage'))
        if 'X-GPGAuth-Verify-Response' not in r.headers:
            validation_errors.append(GPGAuthException('X-GPGAuth-Verify-Response should be set during the verify stage'))
        if 'X-GPGAuth-Refer' in r.headers:
            validation_errors.append(GPGAuthException('X-GPGAuth-Refer should not be set during verify stage'))

        if validation_errors:
            logger.warning(r.headers)
            raise validation_errors.pop()

        if r.headers['X-GPGAuth-Verify-Response'] != self._nonce0:
            raise GPGAuthException('The server decrypted something different than what we sent (%s <> %s)' % (r.headers['X-GPGAuth-Verify-Response'], self._nonce0))
        logger.info('verify_server_identity(): OK')

    # GPGAuth stages in numerical form
    stage0 = verify_server_identity
