# -*- coding: utf-8 -*-
"""Example usage.
"""

from __future__ import unicode_literals

import bottle
from bottle_jwt import (JWTProviderPlugin, jwt_auth_required, BaseBackend)

app = bottle.Bottle()


server_secret = '*Y*^%JHg7623'


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
