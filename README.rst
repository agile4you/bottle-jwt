**bottle_jwt**:  *JSON Web Token authentication plugin for bottle.py*


.. image:: https://travis-ci.org/agile4you/bottle-jwt.svg?branch=master
    :target: https://travis-ci.org/agile4you/bottle-jwt

.. image:: https://coveralls.io/repos/agile4you/bottle-jwt/badge.svg?branch=master&service=github
    :target: https://coveralls.io/github/agile4you/bottle-jwt?branch=master

*Example Usage*

.. code:: python

    import bottle
    from bottle_jwt import JWTProviderPlugin, BaseBackend, jwt_auth_required

    class FakeBackend(BaseBackend):
        def __init__(self, data):
            self._repo = data

        def authenticate_user(self, user_uid, user_secret):
            """Auth backends must implement `authenticate_user` method with this
            signature(user_uid, user_secret).
            """
            if self._repo.get(user_uid) == user_secret:
                return user_uid
            return None

        def get_user(self, user_uid):
            """Auth backends must implement `get_user` method with this
            signature(user_uid).
            """

            return self._repo.get(user_uid)


    backend = FakeBackend({
                           "user1": "123", 
                           "user2":"345"
                           }, 
                          {
                          "user1": {"name":"User number 1"}, 
                          "user2": {"name":"User number 2"}
                          }
                          )

    server_secret = '@#$!@&^%&@^$&'

    #  create a sample app
    app = bottle.Bottle()

    #  create the auth_provider
    provider = JWTProviderPlugin(
        'jwt_auth',
        auth_endpoint='/oauth',
        backend=backend,
        fields=('username', 'password'),
        secret=server_secret
    )

    # install plugin
    app.install(provider)

    # Use the plugin decorator.

    @app.get('/')
    @jwt_auth_required
    def private_resource():
        return "For your eyes only!"

    bottle.run(app=app, port=8081)


*Registered endpoints*::

    - POST /oauth - d {"username": <username>, "password": <password>}.
        *Returns a JSON object*: {"token": <auth_token>}

    - GET / -headers Authorization: JWT <auth_token>.
