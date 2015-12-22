# -*- coding: utf-8 -*-
"""Unit test fixtures for `bottle-jwt` project
"""


import pytest


@pytest.fixture(scope='session')
def request():
    """Fixture for `bottle.request` instance.
    """

    class MockRequest(object):

        content_type = 'x-www-form-urlencoded'

        def __init__(self, data):
            self.forms = data
            self.query = data
            self.__get_header = {}

        def get_header(self, header, default=None):
            return self.__get_header.get(header) or default

        def set_header(self, header, value):
            self.__get_header[header] = value

    return MockRequest


@pytest.fixture(scope='session')
def backend():
    """Fixture for `bottle.request` instance.
    """
    class MockBackend(object):
        def __init__(self, data):
            self._repo = data

        def authenticate_user(self, user_uid, user_secret):
            if self._repo.get(user_uid) == user_secret:
                return user_uid
            return None

        def get_user(self, user_uid):
            if user_uid in self._repo:
                return True
            return None

    return MockBackend
