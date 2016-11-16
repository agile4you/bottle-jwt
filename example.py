# -*- coding: utf-8 -*-
"""Example usage.
"""

from __future__ import unicode_literals

import bottle
from bottle_jwt import (JWTProviderPlugin, jwt_auth_required, BaseBackend)

app = bottle.Bottle()

server_secret = '*Y*^%JHg7623'

class FakeBackend(BaseBackend):
    """Implement a fake Auth backend"""


    def __init__(self, authdata, attrdata):
        self.authrepo = authdata
        self.attrrepo = attrdata


    def authenticate_user(self, user_uid, user_secret):
        """
        User authentication method. All subclasses must implement the
        `authenticate_user` method with the following specs.

        Args:
            user_uid (str): User identity for the backend (email/username).
            user_secret: User secret (password) for backend.

        Returns:
            User id if authentication is succesful or None
        """
        # Yes, it is stupid, but otherwise you could authenticate with no password and a usename that doesnt exist...
        if user_uid is None or user_secret is None:
            return None
        if self.authrepo.get(user_uid) == user_secret:
            return self.authrepo[user_uid]
        return None


    def get_user(self, user_uid):
        """
        User data retrieval method. All subclasses must implement the
        `get_user` method with the following specs.

        Args:
            user_uid (str): User identity in backend.

        Returns:
            User data (dict) if user exists or None.
        """
        return self.attrrepo.get(user_uid) or {"name":"unknown"}


backend = FakeBackend({"user1": "123", "user2":"345"}, {"user1": {"name":"User number 1"}, "user2": {"name":"User number 2"}})

provider_plugin = JWTProviderPlugin(
    keyword='jwt',
    auth_endpoint='/oauth',
    backend=backend,
    fields=('username', 'password'),
    secret=server_secret
)

app.install(provider_plugin)


@app.get('/')
@jwt_auth_required
def private_resource():
    return {"scope": "For your eyes only!"}


bottle.run(app=app, port=9092, host='0.0.0.0', reloader=True)
