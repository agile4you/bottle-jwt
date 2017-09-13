# -*- coding: utf-8 -*-
"""`bottle_jwt.auth` module.

Main auth providers class implementation.
"""

from __future__ import unicode_literals
from __future__ import print_function

import abc
import six
from bottle_jwt.compat import signature

__all__ = ['BaseAuthBackend', ]


@six.add_metaclass(abc.ABCMeta)
class BaseAuthBackend(object):
    """Auth Provider Backend Interface. Defines a standard API for implementation
    in order to work with different backends (SQL, Redis, Filesystem-based, external
    API services, etc.)

    Notes:
        It is not necessary to subclass `BaseAuthBackend` in order to make `bottle-jwt` plugin to
        work, as long as you implement it's API. For example all the following examples are valid.

    Examples:
        >>> class DummyExampleBackend(object):
        ...     credentials = ('admin', 'qwerty')
        ...     user_id = 1
        ...
        ...     def authenticate_user(self, username, password):
        ...         if (username, password) == self.credentials
        ...             return {'user': 'admin', 'id': 1}
        ...         return None
        ...
        ...     def get_user(self, user_id):
        ...         return {'user': 'admin '} if user_id == self.user_id else None
        ...
        >>> class SQLAlchemyExampleBackend(object):
        ...     def __init__(self, some_orm_model):
        ...         self.orm_model = some_orm_model
        ...
        ...     def authenticate(self, username, password):
        ...         return self.orm_model.get(email=username, password=password) or None
        ...
        ...     def get_user(self, user_id):
        ...         return self.orm_model.get(id=user_uid) or None
        ...
        """

    @abc.abstractmethod
    def authenticate_user(self, username, password):  # pragma: no cover
        """User authentication method. All subclasses must implement the
        `authenticate_user` method with the following specs.

        Args:
            username (str): User identity for the backend (email/username).
            password (str): User secret password.

        Returns:
            A dict representing User record if authentication is succesful else None.

        Raises:
            `bottle_jwt.error.JWTBackendError` if any exception occurs.
        """
        pass

    @abc.abstractmethod
    def get_user(self, user_id):  # pragma: no cover
        """User data retrieval method. All subclasses must implement the
        `get_user` method with the following specs.

        Args:
            user_id (object): User identity in backend.

        Returns:
            User data (dict) if user exists or None.

        Raises:
            `bottle_jwt.error.JWTBackendError` if any exception occurs.
        """
        pass

    @classmethod
    def __subclasshook__(cls, subclass):
        """Useful for checking interface for backends that don't inherit from
        BaseAuthBackend.
        """
        if cls is BaseAuthBackend:
            try:
                authenticate_user_signature = set(signature(subclass.authenticate_user).parameters)
                get_user_signature = set(signature(subclass.get_user).parameters)

                return authenticate_user_signature.issuperset({'username', 'password'}) and \
                    get_user_signature.issuperset({'user_id'})

            except AttributeError:
                return False

        return NotImplemented  # pragma: no cover
