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
import sys


if sys.version_info < (3,):
    def b(x):
        return x
else:
    import codecs

    def b(x):
        return codecs.latin_1_encode(x)[0]


logging.basicConfig(level=logging.DEBUG)
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


class JWTReplier(object):
    """Base Class for generating a reply from the Auth provider.
    """

    """This Method will take the success token and generate the JSON Result(if applicable)."""
    def auth_succeeded(self, token_string):
        return {"token": token_string}

    """This Method will take the failure reason and generate the JSON Result(if applicable)."""
    def auth_failed(self, arguments):
        return {"AuthenticationError": arguments}

    """This Method will take the explanation and generate the JSON Result (if applicable)."""
    def auth_required(self, arguments):
        bottle.abort(401, arguments)


class JWTProviderError(Exception):
    """Base module exception.
    """
    pass


class JWTProvider(object):
    """JWT Auth provider concrete class.
    """

    def __init__(self, fields, backend, secret, algorithm='HS256', ttl=None):
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

    def create_token(self, user):
        """Creates a new signed JWT-valid token.

        Args:
            user (str): The user id from self.backend.

        Returns:
            A valid JWT with expiration signature
        """
        payload = {self.user_field.user_id: base64.b64encode(
            b(user)
        ).decode("utf-8")}

        if self.ttl:
            payload['exp'] = self.expires

        logger.debug("Token created for payload: {}".format(str(payload)))

        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def validate_token(self, token=''):
        """Validate JWT token.

        Args:
            token (str): A Json Web token string.

        Returns:
            The decrypted token data (dict)

        Raises:
            JWTProviderError, if no token is provided, or if it is expired.
        """
        try:
            decoded = jwt.decode(
                token.split(" ", 1).pop(),
                self.secret,
                algorithms=self.algorithm
            )

            logger.debug("Token validation passed: {}".format(token))

            user_uid = decoded.get(self.user_field.user_id)

            if not user_uid:
                raise JWTProviderError('Invalid User token')

            if self.backend.get_user(base64.b64decode(
                    b(user_uid)
            ).decode('utf-8')):
                return decoded

            raise JWTProviderError('Invalid User token')

        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            logger.debug("{}: {}".format(e.args[0], token))
            raise JWTProviderError("Invalid auth token provided.")

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
            user_uid = request.json.get(self.user_field.user_id)
            user_secret = request.json.get(self.user_field.password)
        else:
            user_uid = request.forms.get(self.user_field.user_id)
            user_secret = request.forms.get(self.user_field.password)

        user = self.backend.authenticate_user(user_uid, user_secret)

        if user:
            return self.create_token(user)

        raise JWTProviderError("Unable to authenticate User")

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

    def __init__(self, keyword, auth_endpoint, login_enable=True,
                 scope='plugin', replier=JWTReplier(), **kwargs):
        self.keyword = keyword
        self.login_enable = login_enable
        self.scope = scope
        self.provider = JWTProvider(**kwargs)
        self.auth_endpoint = auth_endpoint
        self.replier = replier

    def setup(self, app):  # pragma: no cover
        """Make sure that other installed plugins don't affect the same
        keyword argument and check if metadata is available.
        """

        if self.login_enable:

            #  Route a login handler in bottle.py app instance.
            @app.post(self.auth_endpoint)
            def auth_handler():
                try:
                    token = self.provider.authenticate(bottle.request)
                    return self.replier.auth_succeeded(token.decode("utf-8"))
                except JWTProviderError as e:
                    return self.replier.auth_failed(e.args)

        for other in app.plugins:
            if not isinstance(other, JWTProviderPlugin):
                continue
            if other.keyword == self.keyword:
                raise bottle.PluginError("Found another db plugin "
                                         "with conflicting settings ("
                                         "non-unique keyword).")

    def apply(self, callback, context):  # pragma: no cover
        """Implement bottle.py API version 2 `apply` method.
        """
        def wrapper(*args, **kwargs):
            try:
                self.provider.authorize(bottle.request)
                return callback(*args, **kwargs)
            except JWTProviderError as e:
                return self.replier.auth_required(e.args)

        if self.scope == 'middleware':
            logger.debug("JWT Authentication: {}".format(context.rule))
            return wrapper

        if not hasattr(callback, 'auth_required'):
            return callback

        logger.debug("JWT Authentication: {}".format(context.rule))
        return wrapper
