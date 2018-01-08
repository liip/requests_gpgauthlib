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

logger = logging.getLogger(__name__)


class GPGAuthSession(Session):
    """GPGAuth extension to :class:`requests.Session`.
    """
    def __init__(self, auth_url, server_fingerprint, **kwargs):
        """Construct a new GPGAuth client session.
        :param auth_url: URL to the GPGAuth endpoint (…/auth/)
        :param server_fingerprint: Full PGP fingerprint of the server
        :param kwargs: Arguments to pass to the Session constructor.
        """
        self.auth_url = re.sub(r'/$', '', auth_url)  # Drop the trailing slash
        self._server_fingerprint = server_fingerprint
        super(GPGAuthSession, self).__init__(**kwargs)

    @property
    def gpg(self):
        if hasattr(self, '_gpg'):
            return self._gpg

        # Instantiate GnuPG in a specific directory
        _gpghomedirname = os.path.join(self.workdir, 'gnupg-homedir')
        if not self._permanent_gnupghomedir:
            # Instantiate this as a class attribute to let it be destroyed automagically
            self._temporarygpghomedir = TemporaryDirectory(prefix='python-gpgauth-cli-')
            _gpghomedirname = self._temporarygpghomedir.name
        # Instantiate the GnuPG process
        self._gpg = GPG(homedir=_gpghomedirname)
        return self._gpg
