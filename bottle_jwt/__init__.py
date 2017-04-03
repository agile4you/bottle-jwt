# -*- coding: utf-8 -*-
#
#    Copyright (C) 2015  Papavassiliou Vassilis
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""`bottle-jwt` package.

JSON Web Token Authentication plugin for bottle.py apps.
"""

__author__ = 'Papavassiliou Vassilis'
__date__ = '2017-1-5'
__version__ = '0.5'
__all__ = ['JWTProviderPlugin', 'JWTProvider', 'jwt_auth_required',
           'BaseAuthBackend', 'JWTError', 'JWTBackendError', 'JWTAuthError',
           'JWTForbiddenError', 'JWTUnauthorizedError']

from bottle_jwt.auth import (JWTProvider, JWTProviderPlugin, jwt_auth_required)
from bottle_jwt.backends import BaseAuthBackend
from bottle_jwt.error import (JWTError, JWTBackendError, JWTAuthError,
                              JWTForbiddenError, JWTUnauthorizedError)

import logging


try:  # Python 2.7+
    from logging import NullHandler

except ImportError:  # pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())
