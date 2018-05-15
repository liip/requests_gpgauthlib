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

from .utils import format_protocol_error

logger = logging.getLogger(__name__)

# This is passbolt_api's version
GPGAUTH_SUPPORTED_VERSION = '1.3.0'


def check_verify(response, check_content=False):
    if response.headers.get('X-GPGAuth-Version') != GPGAUTH_SUPPORTED_VERSION:
        logger.warning(
            format_protocol_error(
                'verify',
                response,
                "GPGAuth Version not supported (%s != %s)" % (
                    response.headers.get('X-GPGAuth-Version'),
                    GPGAUTH_SUPPORTED_VERSION
                )
            )
        )
        return False
    if check_content:
        try:
            j = response.json()
        except ValueError:
            logger.warning(format_protocol_error('verify', response, "GPGAuth Verify body is no json"))
            return False
        if 'body' not in j:
            logger.warning(format_protocol_error('verify', response, "GPGAuth Verify has no body"))
            return False
        if 'fingerprint' not in j['body']:
            logger.warning(format_protocol_error('verify', response, "GPGAuth Verify body has no fingerprint"))
        if 'keydata' not in j['body']:
            logger.warning(format_protocol_error('verify', response, "GPGAuth Verify body has no keydata"))
            return False
    return True


def check_server_verify_response(response):
    if response.headers.get('X-GPGAuth-Authenticated') != 'false':
        logger.warning(format_protocol_error('Stage0', response, 'X-GPGAuth-Authenticated should be set to false'))
        return False
    if response.headers.get('X-GPGAuth-Progress') != 'stage0':
        logger.warning(format_protocol_error('Stage0', response, 'X-GPGAuth-Progress should be set to stage0'))
        return False
    if 'X-GPGAuth-User-Auth-Token' in response.headers:
        logger.warning(format_protocol_error('Stage0', response, 'X-GPGAuth-User-Auth-Token should not be set'))
        return False
    if 'X-GPGAuth-Verify-Response' not in response.headers:
        logger.warning(format_protocol_error('Stage0', response, 'X-GPGAuth-Verify-Response should be set'))
        return False
    if 'X-GPGAuth-Refer' in response.headers:
        logger.warning(format_protocol_error('Stage0', response, 'X-GPGAuth-Refer should not be set'))
        return False
    return True


def get_server_fingerprint(response_json):
    return response_json['body']['fingerprint']


def get_server_keydata(response_json):
    return response_json['body']['keydata']


def check_server_login_stage1_response(response):
    if response.headers.get('X-GPGAuth-Authenticated') != 'false':
        logger.warning(format_protocol_error('Stage1', response, 'X-GPGAuth-Authenticated should be set to false'))
        return False
    if response.headers.get('X-GPGAuth-Progress') != 'stage1':
        logger.warning(format_protocol_error('Stage1', response, 'X-GPGAuth-Progress should be set to stage1'))
        return False
    if 'X-GPGAuth-User-Auth-Token' not in response.headers:
        logger.warning(format_protocol_error('Stage1', response, 'X-GPGAuth-User-Auth-Token should be set'))
        return False
    if 'X-GPGAuth-Verify-Response' in response.headers:
        logger.warning(format_protocol_error('Stage1', response, 'X-GPGAuth-Verify-Response should not be set'))
        return False
    if 'X-GPGAuth-Refer' in response.headers:
        logger.warning(format_protocol_error('Stage1', response, 'X-GPGAuth-Refer should not be set'))
        return False
    return True


def check_server_login_stage2_response(response):
    if response.headers.get('X-GPGAuth-Authenticated') != 'true':
        logger.warning(format_protocol_error('Stage2', response, 'X-GPGAuth-Authenticated should be set to true'))
        return False
    if response.headers.get('X-GPGAuth-Progress') != 'complete':
        logger.warning(format_protocol_error('Stage2', response, 'X-GPGAuth-Progress should be set to complete'))
        return False
    if 'X-GPGAuth-User-Auth-Token' in response.headers:
        logger.warning(format_protocol_error('Stage2', response, 'X-GPGAuth-User-Auth-Token should not be set'))
        return False
    if 'X-GPGAuth-Verify-Response' in response.headers:
        logger.warning(format_protocol_error('Stage2', response, 'X-GPGAuth-Verify-Response should not be set'))
        return False
    if 'X-GPGAuth-Refer' not in response.headers:
        logger.warning(format_protocol_error('Stage2', response, 'X-GPGAuth-Refer should be set'))
        return False
    return True
