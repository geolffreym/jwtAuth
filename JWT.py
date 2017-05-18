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

__author__ = 'gmena'
import json
import time
from datetime import datetime

from jwt.exceptions import JWSEncodeError, JWSDecodeError
from jwt.jws import JWS

from jwt import JWTSetting
from jwt.helpers.jwt import load_file_keys, jwk_from


class JWToken(object):
    def __init__(self, crypth='rsa'):
        # Setup
        _is_rsa = crypth != 'oct'
        # Private key load
        _key_load = not _is_rsa and load_file_keys(JWTSetting.JWT_OCT_KEY, 'r') or load_file_keys(
            JWTSetting.JWT_RSA_PRIVATE_KEY
        )

        # Json Web Service
        self.jws = JWS()
        # Algorithm
        self.alg = not _is_rsa and 'HS256' or 'RS256'
        # Private key processing
        self.jwk = not _is_rsa and jwk_from(_key_load) or jwk_from(_key_load, 'pem')

    def jwt_target(self):
        return self.jwk

    def jwt_get_payload(self, user):
        return json.dumps({
            'user': user.pk,
            'email': user.email,
            'exp': time.mktime((datetime.utcnow() + JWTSetting.JWT_EXPIRE).timetuple())
        }).encode()

    def jwt_verify(self, jwt) -> bool:
        return bool(
            self.jwt_decode(
                jwt
            )
        )

    def jwt_encode(self, payload) -> (str, bool):
        try:
            return self.jws.encode(
                message=payload,
                key=self.jwk,
                alg=self.alg
            )
        except JWSEncodeError:
            return False

    def jwt_decode(self, jwt: str) -> (str, bool):
        try:
            return json.loads(
                self.jws.decode(
                    message=jwt,
                    key=self.jwk
                ).decode('utf-8')
            )
        except JWSDecodeError:
            return False

    def get_authorization_header(self, request):
        """
        Return request's 'Authorization:' header, as a bytestring.
        From: https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/authentication.py
        """
        auth = request.META.get('HTTP_AUTHORIZATION', b'')

        if isinstance(auth, str):
            # Work around django test client oddness
            auth = auth.encode('iso-8859-1')

        return auth
