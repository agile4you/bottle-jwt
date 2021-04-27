# -*- coding: utf-8 -*-
"""Unit test fixtures for `bottle-jwt` project
"""

import bottle
import pytest
import webtest
from bottle_jwt2 import JWTProvider, JWTProviderPlugin, jwt_auth_required


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
    auth_db = [
        {'id': 1, 'username': 'pav', 'password': '123', 'age': 29, 'job': 'software developer'},
        {'id': 2, 'username': 'ama', 'password': '456', 'age': 31, 'job': 'dba'},
        {'id': 3, 'username': 'max', 'password': '789', 'age': 28, 'job': 'mobile developer'},
    ]

    class MockBackend(object):
        def __init__(self, data):
            self._repo = data

        def authenticate_user(self, username, password):
            try:
                user_record = [record for record in self._repo
                               if record['username'] == username and
                               record['password'] == password].pop()
            except IndexError:
                return None

            return user_record

        def get_user(self, user_id):
            try:
                user_record = [record for record in self._repo
                               if record['id'] == user_id].pop()
            except IndexError:
                return None

            return {k: user_record[k] for k in user_record if k != 'password'}

    return MockBackend(auth_db)


@pytest.fixture(scope='session')
def jwt_provider(backend):

    provider = JWTProvider(
        fields=('username', 'password'),
        backend=backend,
        secret='my_secret',
        id_field='id',
        ttl=1
    )

    return provider


@pytest.fixture(scope='session')
def bottle_app(backend):
    """pytest fixture for `bottle.Bottle` instance.
    """

    app = bottle.Bottle()

    jwt_plugin = JWTProviderPlugin(
        keyword='jwt',
        auth_endpoint='/auth',
        backend=backend,
        fields=('username', 'password'),
        secret='my_secret',
        ttl=3
    )

    app.install(jwt_plugin)

    @app.get('/')
    @jwt_auth_required
    def private_resource():
        return {'user': bottle.request.get_user()}

    return webtest.TestApp(app)
