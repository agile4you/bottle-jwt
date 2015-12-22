# -*- coding: utf-8 -*-
"""`bottle_jwt.auth` module.

Main auth providers class implementation.
"""

from __future__ import unicode_literals
from __future__ import print_function

import abc
import json
import six

__all__ = ['BaseBackend', 'FileSystemBackend']


class BackendError(Exception):
    """Raises when a backend error occurs.
    """


@six.add_metaclass(abc.ABCMeta)
class BaseBackend(object):
    """Auth Provider Interface.
    """

    @abc.abstractmethod
    def authenticate_user(self, user_uid, user_secret):  # pragma: no cover
        """User authentication method. All subclasses must implement the
        `authenticate_user` method with the following specs.

        Args:
            user_uid (str): User identity for the backend (email/username).
            user_secret: User secret (password) for backend.

        Returns:
            User id if authentication is succesful or None
        """
        pass

    @abc.abstractmethod
    def get_user(self, user_uid):  # pragma: no cover
        """User data retrieval method. All subclasses must implement the
        `get_user` method with the following specs.

        Args:
            user_uid (str): User identity in backend.

        Returns:
            User data (dict) if user exists or None.
        """
        pass


class FileSystemBackend(BaseBackend):
    """A JSON file-system backend system (useful for development only).
    Reads a json file that conforms to the following api:

    {"users": [
        {
            "user_id": "<user_id>",
            "password": "<password>",
            "attr1": value1,
            ...
            ...
        }
    ]
    }

    """

    def __init__(self, storage=''):
        self.storage = storage
        self._data = None

    @property
    def data(self):
        if not self._data:
            try:
                with open(self.storage, 'r') as db_storage:
                    data = db_storage.read()
                self._data = json.loads(data).get('users')

            except IOError as e:
                raise BackendError(e.args)
        return self._data

    def authenticate_user(self, user_uid, user_secret):
        """Implement `BaseBackend.authenticate_user` method.
        """

        try:
            return [user for user in self.data
                    if user['user_id'] == user_uid and
                    user['password'] == user_secret].pop()

        except IndexError:
            return None

    def get_user(self, user_uid):
        """Implement `BaseBackend.get_user` method.
        """
        user = [user for user in self.data if user['user_id'] == user_uid]
        if user:
            return user.pop()
        return None
