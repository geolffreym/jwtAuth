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

import os
import json
from jwt import jwk_from_dict, jwk_from_pem, AbstractJWKBase


def jwt_signature(_sign, alg):
    _is_rsa = alg != 'oct'
    _load = load_file_keys(_sign, not _is_rsa and 'r' or 'rb')
    return jwk_from(_load, not _is_rsa and 'json' or 'pem')


def jwk_from(file_read: bytes, read_as: str = 'json') -> AbstractJWKBase:
    # For PEM read
    if read_as == 'pem':
        return jwk_from_pem(file_read)

    else:
        return jwk_from_dict(
            json.loads(
                str(file_read)
            )
        )


def load_file_keys(name, mode='rb') -> bytes:
    # Get absolute path
    here = os.path.dirname(os.path.join(os.path.dirname(__file__), '../../'))
    abspath = os.path.normpath(os.path.join(here, 'mandm/jwt/keys', name))
    with open(abspath, mode=mode) as fh:
        return fh.read()


def jwt_login(user) -> bool:
    from JWT import JWToken
    # Logged
    _jwt = JWToken()
    payload = _jwt.jwt_get_payload(user)
    return _jwt.jwt_encode(payload)
