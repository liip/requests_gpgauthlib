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

GPGAUTH_VERIFY_URI = '/verify.json'
GPGAUTH_LOGIN_URI = '/login.json'
GPGAUTH_CHECKSESSION_URI = '/checkSession.json'


def get_verify(session):
    return session.get(session.gpgauth_uri(GPGAUTH_VERIFY_URI))


def post_server_verify_token(session, keyid, server_verify_token):
    return session.post(
        session.gpgauth_uri(GPGAUTH_VERIFY_URI),
        json={
          'gpg_auth': {
              'keyid': keyid,
              'server_verify_token': server_verify_token
          }
        }
    )


def post_log_in(session, keyid, user_token_result=None):
    return session.post(
        session.gpgauth_uri(GPGAUTH_LOGIN_URI),
        json={
            'gpg_auth': {
                'keyid': keyid,
                'user_token_result': user_token_result
            }
        }
    )

def check_session_is_valid(session):
    if not session.cookies:
        return False
    check = session.get(session.gpgauth_uri(GPGAUTH_CHECKSESSION_URI))
    return (check.status_code == 200)
