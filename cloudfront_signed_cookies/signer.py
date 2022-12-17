from os.path import exists
from json import dumps
from datetime import datetime, timedelta
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



class Signer():
    HASH_ALGORITHM = 'SHA-384'

    def __init__(self, cloudfront_id: str, priv_key_file: str) -> None:
        self.cloudfront_id: str = cloudfront_id
        if exists(priv_key_file):
            with open(priv_key_file, mode="rb") as priv_file:
                key_bytes = priv_file.read()
                self.priv_key = serialization.load_pem_private_key(
                    key_bytes,
                    password=None
                )
        else:
            raise FileNotFoundError(f"couldn't find private key file: {priv_key_file}")

    def _sign(self, policy: str) -> bytes:
        '''
        generates signature from policy and the private key associated
        with the public key in the CloudFront trusted key group
        '''
        signature: bytes = self.priv_key.sign(
            policy.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH

            ),
            hashes.SHA384()
        )
        return signature

    def _make_canned_policy(self, resource: str, expiration_date: int):
        '''
        returns default canned policy for signed cookies which only
        uses the `DataLessThan` condition
        '''
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
        return self._to_json(policy)
    
    def _to_json(self, s: dict) -> str:
        '''
        converts dict to JSON string stripped of whitespaces
        '''
        return dumps(s).replace(" ", "")

    def generate_cookies(self,
        Resource: str,
        Policy: dict={},
        SecondsBeforeExpires: int=900
    ) -> dict:
        '''
        Args:
            Resource(str): base URL for the resource you want to allow access to
            Policy(dict): custom policy statement for signed cookie 
            SecondsBeforeExpires(int): numbers of seconds before cookie expires, default=900 (15 minutes)

        Returns:
            dict: returns dict containing the CloudFront-Policy, CloudFront-Signature,
                and CloudFront-Key-Pair-Id cookies
        '''
        expires_on: datetime = datetime.now() + timedelta(seconds=SecondsBeforeExpires)

        if Policy:
            policy: str = self._to_json(Policy)
        else:
            policy: str = self._make_canned_policy(resource=Resource, expiration_date=int(expires_on.timestamp()))

        signature: bytes = self._sign(policy)

        cookies = {
            "CloudFront-Policy": b64encode(policy.encode("utf8")).decode(),
            "CloudFront-Signature": b64encode(signature).decode(),
            "CloudFront-Key-Pair-Id": self.cloudfront_id
        }

        return cookies
