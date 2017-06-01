###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) Geolffrey Mena
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################

from django.contrib.auth.models import User
from JWT import JWToken
from jwt import JWTSetting as settings
from django.utils.encoding import smart_text
from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import resolve
from calendar import timegm
from datetime import datetime
# from contextlib import suppress
from lib.JSON import JSON
import time


class JWTAuthMiddleware(object):
    def __init__(self, get_response=None):
        self.get_response = get_response
        self.jwt = JWToken()
        # One-time configuration and initialization.

    def __call__(self, request, *args, **kwargs):
        _response = resolve(request.path)  # Response reverse path

        # Exceptions
        if 'except_jwt' not in _response.kwargs:
            # # Initialize
            try:  # Try access
                # Watch for auth
                _jwtoken = self.handle_request_token(request)
                _payload = self.verify_signature(_jwtoken)
                # If you want the request.user in view after every request uncomment this
                # _user = self.auth_user(_payload)

                # Get user credentials
                # request.user = _payload
                request.token = _jwtoken
                request.payload = _payload

            except SuspiciousOperation as e:
                request.invalid_jwt = True
                return JSON.render_to_response({
                    'status': 'ERROR',
                    'status_message': str(e),
                    'timestamp': int(time.time())
                }, 401)

        # Append kwargs
        request.kwargs = _response.kwargs

        # Code to be executed for each request before
        # the view (and later middleware) are called.
        return self.get_response(
            request
        )

    def handle_request_token(self, request):
        auth = self.jwt.get_authorization_header(request).split()
        auth_header_prefix = settings.JWT_HEADER_PREFIX.lower()

        if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
            raise SuspiciousOperation(
                'Incorrect authentication credentials.'
            )

        if len(auth) == 1:
            raise SuspiciousOperation(
                'Invalid Authorization header. No credentials provided.'
            )

        elif len(auth) > 2:
            raise SuspiciousOperation(
                'Invalid Authorization header. Credentials string should not contain spaces.'
            )

        return auth[1].decode('utf-8')

    # If you want the request.user in view after every request uncomment this
    # def auth_user(self, payload):
    #     try:
    #         user_id = payload['user']
    #         user = User.objects.get(pk=user_id)
    #         user.is_active = True
    #         return user
    #     except User.DoesNotExist:
    #         raise SuspiciousOperation(
    #             'Invalid signature'
    #         )

    def verify_signature(self, jwtoken):
        try:
            # Handle valid token
            if not self.jwt.jwt_verify(jwtoken):
                raise SuspiciousOperation(
                    'Invalid signature'
                )

            # Handle Payload
            payload = self.jwt.jwt_decode(
                jwtoken
            )

            # Check for expire
            if 'exp' in payload and settings.JWT_ALLOW_EXPIRE:
                utc_timestamp = timegm(datetime.utcnow().utctimetuple())

                # Valid if token expire
                if payload['exp'] < (utc_timestamp - settings.JWS_LEEWAY):
                    raise SuspiciousOperation(
                        'Signature has expired'
                    )
        except UnicodeDecodeError:
            raise SuspiciousOperation(
                'Error decoding signature.'
            )

        return payload
