
from unittest import TestCase
from mandm.jwt.JWT import JWToken
from jwt.jwk import OctetJWK


class TestJWSOct(TestCase):
    def setUp(self):
        _jwt = JWToken('oct')
        self.jwk = _jwt.jwt_target()

    def test_is_oct_instance(self):
        assert isinstance(self.jwk, OctetJWK)
