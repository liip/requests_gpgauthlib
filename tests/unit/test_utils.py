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

from mock import call, patch

from test.support import EnvironmentVarGuard

from requests_gpgauthlib.utils import get_workdir


@patch('os.makedirs')
def test_get_workdir_gives_homedir_if_HOME_is_in_env(makedirs, caplog):
    env = EnvironmentVarGuard()
    test_home = '/requests-gpgauth-home'
    env.set('HOME', test_home)
    workdir = os.path.join(test_home, '.config', 'requests_gpgauthlib')
    caplog.set_level(logging.WARNING)

    assert get_workdir() == workdir
    makedirs.assert_called_with(workdir, exist_ok=True)
    assert not caplog.records


@patch('os.makedirs')
def test_get_workdir_gives_tmp_if_HOME_is_not_in_env(makedirs, caplog):
    env = EnvironmentVarGuard()
    env.unset('HOME')
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
    env = EnvironmentVarGuard()
    env.unset('HOME')
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
