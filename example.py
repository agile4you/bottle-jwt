# -*- coding: utf-8 -*-
"""Example usage.
"""

from __future__ import unicode_literals

import bottle
from bottle_jwt import (JWTProviderPlugin, jwt_auth_required, BaseBackend)

app = bottle.Bottle()

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


backend = FakeBackend({"pav": "123", "ama": "123", "max": '456'})

app.install(JWTProviderPlugin(
    'jwt', auth_endpoint='/oauth', backend=backend,
    fields=('username', 'password'), secret='!@#'
))


@app.get('/')
@jwt_auth_required
def private_resource():
    return {"scope": "For your eyes only!"}


bottle.run(app=app, port=9092, host='0.0.0.0', reloader=True)
