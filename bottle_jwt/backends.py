# -*- coding: utf-8 -*-
"""`bottle_jwt.auth` module.

Main auth providers class implementation.
"""

from __future__ import unicode_literals
from __future__ import print_function

import abc
import json
import six


class BackendError(Exception):
    """Raises when a backend error occurs.
    """


@six.add_metaclass(abc.ABCMeta)
class BaseBackend(object):
    """Auth Provider Interface.
    """

    @abc.abstractmethod
    def get_user(self, user_uid, user_secret):  # pragma: no cover
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

    def get_user(self, user_uid, user_secret):
        """Implement `BaseBackend.get_user` method.
        """

        try:
            return [user for user in self.data
                    if user['user_id'] == user_uid
                    and user['password'] == user_secret].pop()
        except IndexError:
            return None
