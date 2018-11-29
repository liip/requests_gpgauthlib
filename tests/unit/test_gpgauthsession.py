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

import pytest

import requests_mock as rm_module

from uuid import uuid4
from urllib.parse import quote

from requests_gpgauthlib.gpgauth_protocol import GPGAUTH_SUPPORTED_VERSION
from requests_gpgauthlib.utils import create_gpg, get_temporary_workdir
from requests_gpgauthlib.gpgauth_session import GPGAuthSession
from requests_gpgauthlib.exceptions import (GPGAuthException, GPGAuthStage0Exception, GPGAuthStage1Exception,
                                            GPGAuthStage2Exception)


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
        # Setup a server
        self.server_gnupg_home = get_temporary_workdir()
        self.server_gpg = create_gpg(self.server_gnupg_home.name)
        input_data = self.server_gpg.gen_key_input(testing=True, key_length=1024, name_email='server@inexistant.example.com')

        # Generate the key, making sure it worked
        self.server_key = self.server_gpg.gen_key(input_data)
        assert self.server_key.fingerprint

        # Export the key, making sure it worked
        self.server_keydata = self.server_gpg.export_keys(self.server_key.fingerprint)
        assert self.server_keydata

        # Setup a user
        self.gnupg_home = get_temporary_workdir()
        self.gpg = create_gpg(self.gnupg_home.name)
        self.ga = GPGAuthSession(self.gpg,
                                 'https://inexistant.example.com/', '/auth/')

        self.user_passphrase = 'user-sicrit-passphrase'
        input_data = self.gpg.gen_key_input(testing=True,
                                            key_length=1024, passphrase=self.user_passphrase,
                                            name_email='user@inexistant.example.com')

        # test_user_fingerprint_raises_without_key
        with pytest.raises(GPGAuthException):
            assert self.ga.user_fingerprint

        # Generate the key, making sure it worked
        self.user_key = self.gpg.gen_key(input_data)
        assert self.user_key.fingerprint

        # Use private API to set the passphrase
        self.ga._user_passphrase = self.user_passphrase

        # Export the user key
        self.user_keydata = self.gpg.export_keys(self.user_key.fingerprint)
        assert self.user_keydata
        # … and import it in the server keyring
        import_result = self.server_gpg.import_keys(self.user_keydata)
        assert self.user_key.fingerprint in import_result.fingerprints

    def test_gpgauth_version_is_supported_not_in_absence_of_headers(self, requests_mock):
        requests_mock.get('/auth/verify.json')
        assert not self.ga.gpgauth_version_is_supported

    def test_gpgauth_version_is_supported_not_for_wrong_versions(self, requests_mock):
        requests_mock.get('/auth/verify.json', headers={'X-GPGAuth-Version': '1.2'})
        assert not self.ga.gpgauth_version_is_supported

    def test_gpgauth_version_is_supported_works(self,  requests_mock):
        requests_mock.get('/auth/verify.json', headers={'X-GPGAuth-Version': '1.3.0'})
        assert self.ga.gpgauth_version_is_supported

    def test_server_fingerprint_raises_if_version_unsupported(self,  requests_mock):
        requests_mock.get('/auth/verify.json', headers={'X-GPGAuth-Version': '-not-1.3.0'})
        with pytest.raises(GPGAuthException):
            assert self.ga.server_fingerprint

    def test_server_fingerprint_empty_body_raises(self,  requests_mock):
        requests_mock.get('/auth/verify.json',
                          headers={'X-GPGAuth-Version': '1.3.0'}
                          )
        with pytest.raises(GPGAuthException):
            assert self.ga.server_fingerprint

    def test_server_fingerprint_key_fingerprint_mismatch_raises(self, requests_mock):
        requests_mock.get('/auth/verify.json',
                          headers={'X-GPGAuth-Version': '1.3.0'},
                          json={
                            'body': {
                              'fingerprint': self.server_key.fingerprint,
                              'keydata': 'mismatch',
                            }
                          }
                          )
        with pytest.raises(GPGAuthException):
            assert self.ga.server_fingerprint

    def test_server_fingerprint_works_with_good_data(self, requests_mock):
        requests_mock.get('/auth/verify.json',
                          headers={'X-GPGAuth-Version': '1.3.0'},
                          json={
                            'body': {
                              'fingerprint': self.server_key.fingerprint,
                              'keydata': self.server_keydata,
                            }
                          }
                          )
        assert self.ga.server_fingerprint == self.server_key.fingerprint

        # Check that the server key was imported
        local_keys = self.gpg.list_keys()
        # Take the fingerprint from the self.ga object on purpose…
        assert self.ga.server_fingerprint in local_keys.fingerprints
        # … to verifiy the get was only performed once
        assert requests_mock.call_count == 1

    def test_nonce0_is_constant(self):
        assert self.ga._nonce0 == self.ga._nonce0

    def test_nonce0_contains_version(self):
        assert GPGAUTH_SUPPORTED_VERSION in self.ga._nonce0

    def test_user_fingerprint_works_with_key(self):
        assert self.ga.user_fingerprint == self.user_key.fingerprint

    def test_server_identity_is_verified_raises(self, requests_mock):
        requests_mock.post('/auth/verify.json',
                           headers={'X-GPGAuth-Authenticated': 'true'}
                           )
        with pytest.raises(GPGAuthStage0Exception):
            assert self.ga.server_identity_is_verified

    def test_server_identity_is_verified_wrong_nonce_raises(self, requests_mock):
        requests_mock.post('/auth/verify.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'false',
                             'X-GPGAuth-Progress': 'stage0',
                             'X-GPGAuth-Verify-Response': 'broken_nonce',
                             }
                           )
        with pytest.raises(GPGAuthStage0Exception):
            assert self.ga.server_identity_is_verified

    def test_server_identity_is_verified(self, requests_mock):
        requests_mock.post('/auth/verify.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'false',
                             'X-GPGAuth-Progress': 'stage0',
                             'X-GPGAuth-Verify-Response': self.ga._nonce0,
                             }
                           )
        assert self.ga.server_identity_is_verified

    def test_user_auth_token_raises_if_cant_decrypt(self, requests_mock):
        requests_mock.post('/auth/login.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'false',
                             'X-GPGAuth-Progress': 'stage1',
                             'X-GPGAuth-User-Auth-Token': 'broken',
                             }
                           )

        with pytest.raises(GPGAuthStage1Exception):
            assert self.ga.user_auth_token

    def test_user_auth_token(self, requests_mock):
        server_nonce = 'gpgauthv{v}|36|{uuid}|gpgauthv{v}'.format(v=GPGAUTH_SUPPORTED_VERSION, uuid=uuid4())
        # The server encrypt it towards the user if the account exists
        user_auth_token = self.server_gpg.encrypt(server_nonce, self.user_key.fingerprint, always_trust=True)
        assert user_auth_token.ok
        # Format the user_auth_token as we see it in the wild
        prepared_user_auth_token = quote(str(user_auth_token)).replace('%20', '+')

        requests_mock.post('/auth/login.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'false',
                             'X-GPGAuth-Progress': 'stage1',
                             'X-GPGAuth-User-Auth-Token': prepared_user_auth_token,
                             }
                           )
        assert self.ga.user_auth_token

    def test_is_authenticated_with_token_raises_with_wrong_headers(self, requests_mock):
        requests_mock.post('/auth/login.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'true',
                             'X-GPGAuth-Progress': 'complete'
                             }
                           )
        with pytest.raises(GPGAuthStage2Exception):
            assert self.ga.is_authenticated_with_token

    def test_is_authenticated_with_token(self, requests_mock):
        requests_mock.post('/auth/login.json',
                           headers={
                             'X-GPGAuth-Authenticated': 'true',
                             'X-GPGAuth-Progress': 'complete',
                             'X-GPGAuth-Refer': 'exists'
                             }
                           )
        assert self.ga.is_authenticated_with_token
