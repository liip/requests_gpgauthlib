# -*- coding: utf-8 -*-
#
# python-gpgauth -- A GPGAuth Client in Python
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
from tempfile import TemporaryDirectory

from pretty_bad_protocol.gnupg import GPG

from .exceptions import GPGAuthKeyImportError

logger = logging.getLogger(__name__)


def format_protocol_error(identifier, response, message):
    gpgauth_debug = response.headers.get('X-GPGAuth-Debug')
    debug_info = ' (Debug: {})'.format(gpgauth_debug) if gpgauth_debug else ''
    return '{identifier}: {message}{debug_info}'.format(identifier=identifier, message=message, debug_info=debug_info)


def get_workdir():
    _userhome = os.environ.get('HOME')
    if not _userhome:
        _userhome = '/tmp/requests_gpgauthlib'
        try:
            os.makedirs(_userhome, exist_ok=True)
            logger.warning('get_workdir: HOME undefined, using {}'.format(_userhome))
        except (OSError, IOError):
            _userhome = os.getcwd()
            logger.warning('get_workdir: HOME undefined and /tmp unwriteable, using {}'.format(_userhome))
    workdir = os.path.join(os.path.join(_userhome, '.config'), 'requests_gpgauthlib')

    try:
        os.makedirs(workdir, exist_ok=True)
    except (OSError, IOError):
        pass

    return workdir


def get_temporary_workdir():
    return TemporaryDirectory(prefix='requests_gpgauthlib-')


def create_gpg(workdir):
    gpg = GPG(homedir=os.path.join(workdir, '.gnupg'))
    gpg.encoding = 'utf-8'
    return gpg


def import_user_private_key_from_file(gpg, user_private_key_file):
    with open(user_private_key_file, 'r') as key:
        logger.info('Importing the user private key; password prompt expected')
        import_result = gpg.import_keys(key.read())
        if len(import_result.fingerprints) < 1:
            raise GPGAuthKeyImportError('No key could be imported')
        else:
            [
                logger.info('GPG key 0x%s successfully imported' % key)
                for key in import_result.fingerprints
            ]
            user_fingerprint = import_result.fingerprints.pop()

    return user_fingerprint
