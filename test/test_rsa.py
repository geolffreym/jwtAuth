from unittest import TestCase

from jwt.jwk import RSAJWK, RSAPrivateKey, AbstractJWKBase
from jwt.jws import JWS

from JWT import JWToken
from helpers.jwt import import load_file_keys, jwk_from


class TestJWSRSA(TestCase):
    def setUp(self):
        # local
        _jwt = JWToken('rsa')

        self.jws = JWS()
        self.jwk = _jwt.jwt_target()

        # Default message
        self.message = b'{"user": 1, "email": "gmjun2000@gmail.com","exp": "1486947255.0"}'

        # Compressed
        self.compact = 'eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjogMSwgImVtYWlsIjogImdtanVuMjAwMEBnbWFpbC5jb20iLCJleHAiOiAiMTQ4Njk0NzI1NS4wIn0.L57CzBbMf1aL413EfmVq_mDNCy6Fyh6zRG3wyh_EZP3kJAY_dnuYyD3siEJT2ebhGVmkB0v6YRT6jshi2gCuiAd4xahwsk9MrNsx0_atPJmzRiJr0sVf19iaaVBuVD8ltDDr8Lhh9ccBLgTmzEsHTzQwA-Krb32yApT5a16Mt_Q'

    def test_is_abstract_jwk(self):
        assert isinstance(self.jwk, AbstractJWKBase)

    def test_is_rsa_instance(self):
        assert isinstance(self.jwk, RSAJWK)
        assert isinstance(self.jwk.keyobj, RSAPrivateKey)

    def test_decode(self):
        _pub = jwk_from(
            load_file_keys(
                'publickey.pem'
            ), 'pem'
        )

        _message = self.jws.decode(
            self.compact, _pub
        )

        self.assertEqual(
            _message,
            self.message
        )

    def test_encode_rsa(self):
        _encode = self.jws.encode(
            message=self.message,
            key=self.jwk,
            alg='RS256'
        )

        self.assertEqual(
            _encode,
            self.compact
        )
