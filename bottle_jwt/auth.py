# -*- coding: utf-8 -*-
"""`bottle_jwt.auth` module.

Main auth providers class implementation.
"""

from __future__ import unicode_literals
from __future__ import print_function

import base64
import bottle
import collections
import jwt
import datetime
import logging
from bottle_jwt.compat import signature
from bottle_jwt.backends import BaseAuthBackend
from bottle_jwt.error import JWTBackendError, JWTAuthError, JWTForbiddenError, JWTUnauthorizedError
from bottle_jwt.compat import b


try:
    import ujson as json

except ImportError:
    try:
        import simplejson as json

    except ImportError:
        import json


logger = logging.getLogger(__name__)


auth_fields = collections.namedtuple('AuthField', 'user_id, password')


def jwt_auth_required(callable_obj):
    """A decorator that signs a callable object with an 'auth_required'
    attribute (True). We use this attribute to find which handler callbacks
    require an authorized for protected access.

    Args:
        callable_obj (instance): A handler callable object.

    Returns:
        The callable object.
    """
    setattr(callable_obj, 'auth_required', True)

    return callable_obj


class JWTProvider(object):
    """JWT Auth provider concrete class.
    """

    def __init__(self, fields, backend, secret, id_field='id', algorithm='HS256', ttl=None):
        if not isinstance(backend, BaseAuthBackend):  # pragma: no cover
            raise TypeError('backend instance does not implement {} interface'.format(BaseAuthBackend))

        self.id_field = id_field
        self.user_field = auth_fields(*fields)
        self.secret = secret
        self.backend = backend
        self.algorithm = algorithm
        self.ttl = ttl

    @property
    def expires(self):
        """Computes the token expiration time based on `self.ttl` attribute.
        """
        return datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.ttl
        )

    def create_token(self, user, ttl=None):
        """Creates a new signed JWT-valid token.

        Args:
            user (dict): The user record in key/value mapping from instance backend.
            ttl (int): Optional time to live value.

        Returns:
            A valid JWT with expiration signature
        """
        user_id = json.dumps(user.get(self.id_field)).encode('utf-8')

        payload = {'sub': base64.b64encode(bytes(user_id)).decode("utf-8")}

        if self.ttl:
            # you can override instance default ttl in special cases.
            if ttl:
                payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)

            else:
                payload['exp'] = self.expires

        logger.debug("Token created for payload: {}".format(str(payload)))

        return jwt.encode(payload, self.secret, algorithm=self.algorithm), payload['exp']

    def validate_token(self, token=''):
        """Validate JWT token.

        Args:
            token (str): A Json Web token string.

        Returns:
            The decrypted token data (dict)

        Raises:
            JWTProviderError, if no token is provided, or if it is expired.
        """
        if not token:
            logger.debug("Forbidden access")
            raise JWTForbiddenError('Cannot access this resource!')

        try:
            decoded = jwt.decode(
                token.split(" ", 1).pop(),
                self.secret,
                algorithms=self.algorithm
            )

            logger.debug("Token validation passed: {}".format(token))

            user_uid = decoded.get('sub')

            if not user_uid:  # pragma: no cover
                raise JWTUnauthorizedError('Invalid User token')

            user = self.backend.get_user(json.loads(base64.b64decode(user_uid).decode('utf-8')))

            if user:
                return user

            raise JWTUnauthorizedError('Invalid User token')

        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            logger.debug("{}: {}".format(e.args[0], token))
            raise JWTUnauthorizedError("Invalid auth token provided.")

    def authenticate(self, request):
        """Returns a valid JWT for provided credentials.

        Args:
            request (instance): bottle.request instance.

        Returns:
            A JWT token string.

        Raises:
            BackendError, if an auth backend error occurs.
            JWTProviderError,, if user can't be authorized.
        """
        if request.content_type.startswith('application/json'):  # pragma: no cover
            try:
                username = request.json.get(self.user_field.user_id)
                password = request.json.get(self.user_field.password)
            except (AttributeError, json.decoder.JSONDecodeError):
                raise JWTAuthError("Unable to authenticate User")

        else:
            username = request.forms.get(self.user_field.user_id)
            password = request.forms.get(self.user_field.password)

        user = self.backend.authenticate_user(username, password)

        if user:
            return self.create_token(user)

        raise JWTAuthError("Unable to authenticate User")

    def authorize(self, request):
        """Checks if incoming request is authenticated.

        Args:
            request (instance): bottle.request instance.

        Returns:
            Request JWT decrypted payload, if request is authenticated else
            False.

        Raises:
            JWTProvider, if no auth header if present or invalid/expired
            token is provided.
        """
        user_token = request.get_header("Authorization", '')
        return self.validate_token(user_token) or False


class JWTProviderPlugin(object):
    """A `bottle.Bottle` application plugin for JWTProvider.

    Attributes:
        keyword (str): The string keyword for application registry.
        provider (instance): A JWTProvider instance.
        login_enable (bool): If True app is mounted with a login handler.
        auth_endpoint (str): The authentication uri for provider if
                             login_enabled is True.
        kwargs : JWTProvider init parameters.
    """
    scope = ('plugin', 'middleware')
    api = 2

    def __init__(self, keyword, auth_endpoint, login_enable=True, scope='plugin', **kwargs):
        self.keyword = keyword
        self.login_enable = login_enable
        self.scope = scope
        self.provider = JWTProvider(**kwargs)
        self.auth_endpoint = auth_endpoint

    def setup(self, app):  # pragma: no cover
        """Make sure that other installed plugins don't affect the same
        keyword argument and check if metadata is available.
        """

        if self.login_enable:

            #  Route a login handler in bottle.py app instance.
            @app.post(self.auth_endpoint)
            def auth_handler():
                try:
                    token, expires = self.provider.authenticate(bottle.request)
                    return {"token": token.decode("utf-8"), "expires": str(expires)}

                except JWTAuthError as error:
                    return {"AuthError": error.args[0]}

                except JWTBackendError:
                    return {"AuthBackendError": "Try later or contact admin!"}

        for other in app.plugins:
            if not isinstance(other, JWTProviderPlugin):
                continue

            if other.keyword == self.keyword:
                raise bottle.PluginError("Found another JWT plugin "
                                         "with conflicting settings ("
                                         "non-unique keyword).")

    def apply(self, callback, context):  # pragma: no cover
        """Implement bottle.py API version 2 `apply` method.
        """

        _signature = signature(callback).parameters

        def injected(*args, **kwargs):
            if self.keyword in _signature:
                kwargs[self.keyword] = self.provider
            return callback(*args, **kwargs)

        def wrapper(*args, **kwargs):
            try:
                user = self.provider.authorize(bottle.request)
                setattr(bottle.request, 'get_user', lambda _: user)
                return injected(*args, **kwargs)

            except JWTUnauthorizedError as error:
                bottle.response.content_type = b('application/json')
                bottle.response._status_line = b('401 Unauthorized')
                return {"AuthError": error.args}

            except JWTForbiddenError as error:
                bottle.response.content_type = b('application/json')
                bottle.response._status_line = b('403 Forbidden')
                return {"AuthError": error.args}

            except JWTBackendError:
                bottle.response.content_type = b('application/json')
                bottle.response._status_line = b('503 Service Unavailable')
                return {"AuthBackendException": "Try later or contact admin!"}

        if self.scope == 'middleware':
            logger.debug("JWT Authentication: {}".format(context.rule))
            return wrapper

        if not hasattr(callback, 'auth_required'):
            return injected

        logger.debug("JWT Authentication: {}".format(context.rule))
        return wrapper
