# -*- coding: utf-8 -*-
"""`bottle_jwt.auth` module.

Main auth providers class implementation.
"""

from __future__ import unicode_literals
from __future__ import print_function

import abc
import json
import requests
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
                    if user['user_id'] == user_uid and
                    user['password'] == user_secret].pop()

        except IndexError:
            return None


class ExternalAPIBackend(BaseBackend):  # pragma: no cover
    """Use another authentication web service as a backend provider for
    JWT Authentication. The external API must at least uses password
    authentication scheme.

    # TODO (vapapvasil@gmail.com) Work with Google, Facebook, Twitter Oauth
    protocols.

    Attributes:
        auth_service (str): The Full endpoint to the external auth service.
        method (str): The HTTP method name.
    """

    def __init__(self, srv_host, srv_port, srv_uri, method='POST',
                 ssh=True):
        """
        """
        self.auth_service = '{}:://{}:{}/{}'.format(
            'https' if ssh else 'http',
            srv_host,
            srv_port,
            srv_uri
        )

        self.method = method.lower()

    def get_user(self, user_uid, user_secret, **extras):
        """Implement `BaseBackend.get_user` method.
        """

        auth_proxy = getattr(self.http_engine, self.method)

        try:
            user_data = auth_proxy(self.uri)

        except (requests.ConnectionError, requests.HTTPError) as e:

            raise BackendError("ExternalAuthServiceError: {}".format(e.args))

        return user_data or None
