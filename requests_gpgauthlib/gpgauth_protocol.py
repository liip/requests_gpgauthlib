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

GPGAUTH_SUPPORTED_VERSION = "1.3.0"


def check_verify_headers(response_headers):
    if 'X-GPGAuth-Version' not in response_headers:
        logger.debug(response_headers)
        return False
    if response_headers['X-GPGAuth-Version'] != GPGAUTH_SUPPORTED_VERSION:
        logger.warning(
            "GPGAuth Version not supported (%s != %s)",
            response_headers['X-GPGAuth-Version'],
            GPGAUTH_SUPPORTED_VERSION
        )
        return False
    return True
