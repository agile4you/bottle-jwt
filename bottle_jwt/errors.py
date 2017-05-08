# -*- coding: utf-8 -*-
"""`bottle_jwt.error` module.

Provides Exception hierarchy.
"""


class JWTError(Exception):
    """Base package Error
    """
    pass


class JWTBackendError(JWTError):
    """`bottle_jwt.backend` module base Error class.
    """
    pass


class JWTProviderError(JWTError):
    """`bottle_jwt.auth` module base Error class.
    """
    pass
