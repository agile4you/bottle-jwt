**bottle_jwt**:  *JSON Web Token authentication plugin for bottle.py*


.. image:: https://travis-ci.org/agile4you/bottle-jwt.svg?branch=master
    :target: https://travis-ci.org/agile4you/bottle-jwt

.. image:: https://coveralls.io/repos/agile4you/bottle-jwt/badge.svg?branch=master&service=github
    :target: https://coveralls.io/github/agile4you/bottle-jwt?branch=master

*Example Usage*

.. code::


    >>> import bottle
    >>> from bottle_jwt import JWTProviderPlugin, BaseBackend, jwt_auth_required
    >>>
    >>> class FakeBackend(BaseBackend):
    ...     """Implement a fake Auth backend"""
    ...     def __init__(self, data):
    ...         self.repo = data
    ...     def get_user(self, user_uid, user_secret):
    ...         """Auth backends must implement get_user method with this
    ...         signature(user_uid, user_secret).
    ...         """
    ...         if self.repo.get(user_uid) == user_secret:
    ...             return {"user": self.repo[user_uid]}
    ...         return None
    ...
    >>> backend = FakeBackend({"user1": "123", "user2": "345"})
    >>>
    >>> server_secret = '@#$!@&^%&@^$&'
    >>> #  create a sample app
    >>> app = bottle.Bottle()
    >>>
    >>> #  create the auth_provider
    >>> provider = JWTProviderPlugin(
    ...     'jwt_auth',
    ...     auth_endpoint='/oauth',
    ...     backend=backend,
    ...     fields=('username', 'password'),
    ...     secret=server_secret
    ... )
    >>>
    >>> # install plugin
    >>> app.install(provider)
    >>>
    >>> # decorated views.
    >>> @app.get('/')
    ... @jwt_auth_required
    ... def private_resource():
    ...     return "For your eyes only!"
    ...
    >>> bottle.run(app=app, port=8081)


*Registered endpoints*

    - POST /oauth - d {"username": <username>, "password": <password>}.
        *Returns a JSON object*: {"token": <auth_token>}

    - GET / -headers Authorization: JWT <auth_token>.