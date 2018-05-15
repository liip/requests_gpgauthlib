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
import pytest
import os

from gnupg import GPG
from mock import call, patch
from tempfile import NamedTemporaryFile
from tempfile import TemporaryDirectory
from test.support import EnvironmentVarGuard
from unittest import mock

from requests_gpgauthlib.utils import (
    create_gpg, format_protocol_error, get_temporary_workdir, get_workdir, import_user_private_key_from_file
)
from requests_gpgauthlib.exceptions import GPGAuthKeyImportError


def test_format_protocol_error():
    r = mock.Mock(headers={})
    assert format_protocol_error('id', r, 'message') == 'id: message'

    r2 = mock.Mock(headers={'X-GPGAuth-Debug': 'beetle'})
    assert format_protocol_error('id', r2, 'message') == 'id: message (Debug: beetle)'


@patch('os.makedirs')
def test_get_workdir_gives_homedir_if_HOME_is_in_env(makedirs, caplog):
    homedir = TemporaryDirectory(suffix='-home')
    EnvironmentVarGuard().set('HOME', homedir.name)
    workdir = os.path.join(homedir.name, '.config', 'requests_gpgauthlib')
    caplog.set_level(logging.WARNING)

    assert get_workdir() == workdir
    makedirs.assert_called_with(workdir, exist_ok=True)
    assert not caplog.records


@patch('os.makedirs')
def test_get_workdir_gives_tmp_if_HOME_is_not_in_env(makedirs, caplog):
    EnvironmentVarGuard().unset('HOME')
    workdir = os.path.join('/tmp/requests_gpgauthlib', '.config', 'requests_gpgauthlib')
    caplog.set_level(logging.WARNING)

    assert get_workdir() == workdir
    makedirs.assert_has_calls([
        call('/tmp/requests_gpgauthlib', exist_ok=True),
        call(workdir, exist_ok=True),
    ])
    assert caplog.record_tuples == [
        ('requests_gpgauthlib.utils', logging.WARNING, 'get_workdir: HOME undefined, using /tmp/requests_gpgauthlib')
    ]


def makedirs_fails_in_tmp(path, exist_ok=False):
    if '/tmp/' in path:
        raise OSError
    return


@patch('os.getcwd', return_value='/cwd')
@patch('os.makedirs', side_effect=makedirs_fails_in_tmp)
def test_get_workdir_gives_cwd_if_HOME_is_not_in_env_and_tmp_unwriteable(makedirs, getcwd, caplog):
    EnvironmentVarGuard().unset('HOME')
    workdir = os.path.join('/cwd', '.config', 'requests_gpgauthlib')
    caplog.set_level(logging.WARNING)

    assert get_workdir() == workdir
    makedirs.assert_has_calls([
        call('/tmp/requests_gpgauthlib', exist_ok=True),
        call(workdir, exist_ok=True),
    ])
    assert caplog.record_tuples == [
        ('requests_gpgauthlib.utils', logging.WARNING, 'get_workdir: HOME undefined and /tmp unwriteable, using /cwd')
    ]


def test_get_temporary_workdir_is_prefixed():
    assert 'requests_gpgauthlib-' in get_temporary_workdir().name


def test_get_temporary_workdir_is_different():
    assert get_temporary_workdir().name != get_temporary_workdir().name


def test_create_gpg_gives_a_GPG_object():
    workdir = get_temporary_workdir()
    assert isinstance(create_gpg(workdir.name), GPG)


def test_create_gpg_has_its_home_where_we_say_we_want_it():
    workdir = get_temporary_workdir()
    gpg = create_gpg(workdir.name)
    assert workdir.name in gpg.gnupghome


def test_import_user_private_key_from_inexistant_file_raises():
    gpghome = get_temporary_workdir()
    gpg = create_gpg(gpghome.name)
    with pytest.raises(FileNotFoundError):
        import_user_private_key_from_file(gpg, '/inexistant')


def test_import_user_private_key_from_empty_file_raises():
    gpghome = get_temporary_workdir()
    gpg = create_gpg(gpghome.name)
    with NamedTemporaryFile(mode='w') as empty_key_file:
        with pytest.raises(GPGAuthKeyImportError):
            import_user_private_key_from_file(gpg, empty_key_file.name)


def test_import_user_private_key_from_file_works(caplog):
    gpg_generator_home = get_temporary_workdir()
    gpg_generator = create_gpg(gpg_generator_home.name)

    # Generate a key
    passphrase = 'test-passphrase'
    input_data = gpg_generator.gen_key_input(key_length=1024, passphrase=passphrase)

    # Generate the key, making sure it worked
    key = gpg_generator.gen_key(input_data)
    assert key.fingerprint

    # Export the key, making sure it worked
    key_asc = gpg_generator.export_keys(
        key.fingerprint,
        armor=True, minimal=True,
        secret=True, passphrase=passphrase)
    assert key_asc

    # Create a temporary file, and use it
    with NamedTemporaryFile(mode='w') as private_key_file:
        private_key_file.write(key_asc)
        private_key_file.flush()

        # Setup a different gpg home
        gpg_home = get_temporary_workdir()
        gpg = create_gpg(gpg_home.name)

        caplog.set_level(logging.INFO)

        imported_fingerprint = import_user_private_key_from_file(gpg, private_key_file.name)
        # Check that it really worked
        assert imported_fingerprint == key.fingerprint
        # That we logged what we wanted
        assert caplog.record_tuples == [
            ('requests_gpgauthlib.utils', logging.INFO, 'Importing the user private key; password prompt expected'),
            ('requests_gpgauthlib.utils', logging.INFO, 'GPG key 0x%s successfully imported' % key.fingerprint),
            # FIXME: Check why that message is output twice
            ('requests_gpgauthlib.utils', logging.INFO, 'GPG key 0x%s successfully imported' % key.fingerprint)
        ]
