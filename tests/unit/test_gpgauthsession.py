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

import json
import pytest

from mock import patch

from requests import Response
from requests.structures import CaseInsensitiveDict
import requests_mock as rm_module

from requests_gpgauthlib.utils import create_gpg, get_temporary_workdir
from requests_gpgauthlib.gpgauth_session import GPGAuthSession
from requests_gpgauthlib.exceptions import GPGAuthException



@pytest.fixture
def requests_mock(request):
    with rm_module.Mocker() as m:
        yield m


def test_init_void():
    # No Arguments, it fails
    with pytest.raises(TypeError):
        GPGAuthSession()


class TestGPGAuthSession:

    def setup_class(self):
        # Setup
        self.gpg = create_gpg(get_temporary_workdir().name)
        self.ga = GPGAuthSession(self.gpg,
                                 'https://inexistant.example.com/', '/auth/',
                                 '6810A8F7728F4A7CE936F93BA27743FA0C9E83E0')

    def test_gpgauth_version_is_supported_not_in_absence_of_headers(self, requests_mock):
        requests_mock.get('/auth/verify.json')
        assert not self.ga.gpgauth_version_is_supported

    def test_gpgauth_version_is_supported_not_for_wrong_versions(self, requests_mock):
        requests_mock.get('/auth/verify.json', headers={'X-GPGAuth-Version': '1.2'})
        assert not self.ga.gpgauth_version_is_supported

    def test_gpgauth_version_is_supported_works(self,  requests_mock):
        requests_mock.get('/auth/verify.json', headers={'X-GPGAuth-Version': '1.3.0'})
        assert self.ga.gpgauth_version_is_supported
