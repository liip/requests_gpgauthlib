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
import os

from test.support import EnvironmentVarGuard

from requests_gpgauthlib.utils import get_workdir


def test_get_workdir_gives_homedir_if_HOME_is_in_env():
    env = EnvironmentVarGuard()
    test_home = '/requests-gpgauth-home'
    env.set('HOME', test_home)
    assert get_workdir() == os.path.join(test_home, '.config', 'requests_gpgauthlib')
