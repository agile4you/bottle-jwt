# -*- coding: utf-8 -*-
"""Unit test suite for `bottle_jwt` plugin.
"""
from __future__ import unicode_literals
from __future__ import print_function


import pytest
from bottle_jwt import BaseAuthBackend, JWTAuthError, JWTForbiddenError, JWTUnauthorizedError
from bottle_jwt.compat import b
import time


def test_backend_interface_check_pass(backend):
    """Testing for backend interface check pass.
    """
    assert isinstance(backend, BaseAuthBackend)


def test_backend_interface_check_fail():
    """Testing for backend interface check fail.
    """
    class IncompleteBackend(object):
        def get_user(self, user_id):
            pass

    assert not isinstance(IncompleteBackend(), BaseAuthBackend)


def test_provider_authenticate_pass(jwt_provider, request):
    """Testing `bottle_jwt.auth.JWTProvider.authenticate` method pass.
    """

    req = request({'username': 'pav', 'password': '123'})

    assert jwt_provider.authenticate(req)


def test_provider_authenticate_fail(jwt_provider, request):
    """Testing `bottle_jwt.auth.JWTProvider.authenticate` method fail.
    """

    req = request({'username': 'pav', 'password': '1234'})

    with pytest.raises(JWTAuthError):
        jwt_provider.authenticate(req)


def test_provider_authorize_pass(jwt_provider, request):
    """Testing `bottle_jwt.auth.JWTProvider.authorize` method pass.
    """
    req = request({'username': 'pav', 'password': '123'})

    token = jwt_provider.authenticate(req)

    req.set_header('Authorization', 'JWT {}'.format(token.decode("utf-8")))

    assert jwt_provider.authorize(req)['username'] == 'pav'


def test_provider_authorize_fail(jwt_provider, request):
    """Testing `bottle_jwt.auth.JWTProvider.authorize` method pass.
    """
    req = request({'username': 'pav', 'password': '123'})

    token = jwt_provider.authenticate(req)

    # test for invalid token
    req.set_header('Authorization', 'JWT {}'.format(token[:-1].decode("utf-8")))

    with pytest.raises(JWTUnauthorizedError):
        jwt_provider.authorize(req)

    # test for no token at all
    with pytest.raises(JWTForbiddenError):
        jwt_provider.authorize(request({'username': 'pav', 'password': '123'}))

    # test for expired token
    req.set_header('Authorization', 'JWT {}'.format(token.decode("utf-8")))
    time.sleep(2)

    with pytest.raises(JWTUnauthorizedError):
        jwt_provider.authorize(req)


def test_auth_plugin_login_pass(bottle_app):
    """Test `bottle_jwt.JWTProviderPlugin` login web handler pass.
    """

    data = bottle_app.post_json('/auth', {'username': 'pav', 'password': '123'})

    assert 'token' in data.json


def test_auth_plugin_login_fail(bottle_app):
    """Test `bottle_jwt.JWTProviderPlugin` login web handler fail.
    """

    data = bottle_app.post_json('/auth', {'username': 'pav', 'password': '12'})

    assert data.json == {"AuthError": "Unable to authenticate User"}


def test_auth_plugin_authentication_pass(bottle_app):
    """Test `bottle_jwt.JWTProviderPlugin` authentication pass.
    """

    login = bottle_app.post_json('/auth', {'username': 'pav', 'password': '123'}).json

    resource = bottle_app.get(
        '/',
        extra_environ=dict(HTTP_AUTHORIZATION=b('JWT {}'.format(login['token'])))
    )

    assert resource.json


def test_auth_plugin_authentication_fail(bottle_app):
    """Test `bottle_jwt.JWTProviderPlugin` authentication pass.
    """

    login = bottle_app.post_json('/auth', {'username': 'pav', 'password': '123'}).json

    # test with no auth

    response = bottle_app.get('/', expect_errors=True)

    assert response.status == '403 Forbidden'

    # test for expired token

    time.sleep(4)

    response = bottle_app.get(
        '/',
        expect_errors=True,
        extra_environ=dict(HTTP_AUTHORIZATION=b('JWT {}'.format(login['token'])))
    )

    assert response.status == '401 Unauthorized'
