
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

logger = logging.getLogger(__name__)


class GPGAuthAPI():
    """ Handles the network calls to the GPGAuth API
    """
    def __init__(self, session, auth_url):
        self.session = session
        self.auth_url = auth_url

    def _get(self, uri):
        return self.session.get(self.auth_url + uri)

    def verify(self):
        return self._get('/verify.json')
