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
__date__ = '2015-12-10'
__version__ = '0.0.1'
__all__ = ['JWTProviderPlugin', 'JWTProvider', 'JWTProviderError',
           'BaseBackend', 'BackendError', 'FileSystemBackend']

from .backends import (BaseBackend, FileSystemBackend, BackendError)
from .auth import (JWTProviderError, JWTProvider, JWTProviderPlugin)
