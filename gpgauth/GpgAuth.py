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
import uuid

from distutils.version import StrictVersion

from .exceptions import GPGAuthException

# This is passbolt_api's version
GPGAUTH_MINVERSION = '1.3.0'

logger = logging.getLogger(__name__)


class GPGAuth:
    """ GPGAuth client Class """

    def __init__(self, root_url, fingerprint):
        self.root_url = root_url
        self.fingerprint = fingerprint

    @property
    def _verifyToken(self):
      try:
          self.__verifyToken
      except AttributeError:
          self.__verifyToken  = 'gpgauthv1.3.0|36|';
          self.__verifyToken += uuid.uuid4().hex;
          self.__verifyToken += '|gpgauthv1.3.0';
      return self.__verifyToken


    def stage0(self):
        return self.verify_server_identity()

    def verify_gpgauth_version(self):
        try:
            return self.gpgauth_version_ok == True
        except AttributeError:
            logger.info('Verify support and version')
            r = requests.head(self.root_url + '/auth/')
            if 'X-GPGAuth-Version' not in r.headers:
                raise GPGAuthException("GPGAuth support not announced by %s" % self.root_url)
            if StrictVersion(r.headers['X-GPGAuth-Version']) < StrictVersion(GPGAUTH_MINVERSION):
                raise GPGAuthException("GPGAuth Version too low (%s < %s)" % (r.headers['X-GPGAuth-Version'], GPGAUTH_MINVERSION))
            self.gpgauth_version_ok = True

            # Take the information from the server if they give them
            self.login_url = self.root_url + '/auth/login'
            if 'X-GPGAuth-Login-Url' in r.headers:
                self.login_url = self.root_url + r.headers['X-GPGAuth-Login-Url']

    def verify_server_identity(self):
        self.verify_gpgauth_version()

        print(self._verifyToken)

    #this._generateVerifyToken();

    #return Crypto
      #.encrypt(this.domain.publicKey.fingerprint, this.token)
      #.then(function(encrypted) {
        #return _this.post({
          #url: _this.URL_VERIFY,
          #form: {
            #'data[gpg_auth][keyid]' : _this.user.privateKey.fingerprint,
            #'data[gpg_auth][server_verify_token]' : encrypted
          #}
        #});
      #})
      #.then(function(results) {
        #return _this._onVerifyResponse(results);
      #})
      #.catch(function(err) {
        #throw err;
      #});
  #}

        #print(self.gpgauth_version_ok)
        return False
