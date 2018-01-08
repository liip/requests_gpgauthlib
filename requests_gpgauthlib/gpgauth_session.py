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

from .exceptions import GPGAuthException

# This is passbolt_api's version
GPGAUTH_SUPPORTED_VERSION = '1.3.0'

logger = logging.getLogger(__name__)


class GPGAuthSession(Session):
    """GPGAuth extension to :class:`requests.Session`.
    """
    VERIFY_URI = '/verify.json'

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
    def workdir(self):
        if hasattr(self, '_workdir'):
            return self._workdir
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
        if hasattr(self, '_gpg'):
            return self._gpg

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
        if hasattr(self, '_gpgauth_version_is_supported'):
            return self._gpgauth_version_is_supported is True

        r = self.head(self.auth_url)
        if 'X-GPGAuth-Version' not in r.headers:
            logger.debug(r.headers)
            raise GPGAuthException(
                "GPGAuth support not announced by %s" % self.auth_url
            )
        if r.headers['X-GPGAuth-Version'] != GPGAUTH_SUPPORTED_VERSION:
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
    def server_key(self):
        if hasattr(self, '_server_key'):
            return self._server_key

        if not self.gpgauth_version_is_supported:
            return False

        # Try to get them from GPG
        server_key = self.gpg.export_keys([self._server_fingerprint], secret=False, subkeys=False)
        if 'BEGIN PGP PUBLIC KEY BLOCK' in server_key:
            self._server_key = server_key
            return self._server_key

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

        return self._server_key
