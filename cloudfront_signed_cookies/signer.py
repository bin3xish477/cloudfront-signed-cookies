import re
from _pytest.monkeypatch import resolve
from rsa import sign as sign_with_rsa
from os.path import exists
from json import dumps
from datetime import datetime, timedelta
from base64 import b64encode


HASH_ALGO = 'SHA-384'

class Signer:
    def __init__(self, cloudfront_id: str, priv_key_file: str, expiration: int=900) -> None:
        self.cloudfront_id: str = cloudfront_id
        if exists(priv_key_file):
            with open(priv_key_file) as priv_file:
                self.priv_key = priv_file.read()
        self.expiration = expiration
        self.priv_key = None

    def _sign(self, policy: str) -> bytes:
        signature = sign_with_rsa(policy.encode(), self.priv_key, HASH_ALGO)
        return signature

    def _make_policy(self, resource: str, expiration_date: int):
        policy = {
            'Statement': [{
                'Resource': resource,
                'Condition': {
                    'DateLessThan': {
                        'AWS:EpochTime': expiration_date
                    }
                }
            }]
        }
        return dumps(policy).replace(" ", "")

    def generate_cookies(self, resource, seconds_before_expires: int) -> dict:
        now = datetime.now()
        expires_on = now + timedelta(seconds=seconds_before_expires)
        policy = self._make_policy(resource=resource, expiration_date=int(expires_on.timestamp()))
        signature = self._sign(policy)

        cookies = {
            "CloudFront-Policy": b64encode(policy.encode("utf8")),
            "CloudFront-Signature": b64encode(signature),
            "CloudFront-Key-Pair-Id": ""
        }

        return cookies
