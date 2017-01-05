# -*- coding: utf-8 -*-
"""`bottle_jwt.error` module.

Provides package Exception hierarchy.
"""


class JWTError(Exception):
    """Base package Error class.
    """
    pass


class JWTBackendError(JWTError):
    """Raises when an authentication backend Error occurs.
    """
    pass


class JWTAuthError(JWTError):
    """Raises when an authentication provider error occurs.
    """
    pass


class JWTUnauthorizedError(JWTAuthError):
    """Raises when Unauthorized access occurs.
    """
    pass


class JWTForbiddenError(JWTAuthError):
    """Raises when no authorized access requests protected resource.
    """
    pass
