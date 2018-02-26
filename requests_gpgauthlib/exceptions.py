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


class GPGAuthException(Exception):
    """ Base GPGAuth Exception """
    pass


class GPGAuthStage0Exception(GPGAuthException):
    """ GPGAuth stage0 (server verification) Exception """
    pass


class GPGAuthStage1Exception(GPGAuthException):
    """ Base GPGAuth stage1 (login) Exception """
    pass


class GPGAuthStage2Exception(GPGAuthException):
    """ Base GPGAuth stage2 (Authentication) Exception """
    pass


class GPGAuthNoSecretKeyError(GPGAuthException):
    pass


class GPGAuthKeyImportError(GPGAuthException):
    pass
