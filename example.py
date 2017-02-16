# -*- coding: utf-8 -*-
"""Example usage.
"""

from __future__ import unicode_literals
import bottle
from bottle_jwt import (JWTProviderPlugin, jwt_auth_required)


app = bottle.Bottle()

server_secret = '*Y*^%JHg7623'


class AuthBackend(object):
    """Implementing an auth backend class with at least two methods.
    """
    user = {'id': 1237832, 'username': 'pav', 'password': '123', 'data': {'sex': 'male', 'active': True}}

    def authenticate_user(self, username, password):
        """Authenticate User by username and password.

        Returns:
            A dict representing User Record or None.
        """
        if username == self.user['username'] and password == self.user['password']:
            return self.user
        return None

    def get_user(self, user_id):
        """Retrieve User By ID.

        Returns:
            A dict representing User Record or None.
        """
        if user_id == self.user['id']:
            return {k: self.user[k] for k in self.user if k != 'password'}
        return None


provider_plugin = JWTProviderPlugin(
    keyword='jwt',
    auth_endpoint='/auth',
    backend=AuthBackend(),
    fields=('username', 'password'),
    secret=server_secret,
    ttl=30
)

app.install(provider_plugin)


@app.get('/')
@jwt_auth_required
def private_resource(jwt):
    print(jwt)
    return {"scope": "For your eyes only!", "user": bottle.request.get_user()}


bottle.run(app=app, port=9092, host='0.0.0.0', reloader=True)
