from os.path import exists
from json import dumps
from datetime import datetime, timedelta
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cloudfront_signed_cookies.errors import PrivateKeyNotFound

class Signer():
    HASH_ALGORITHM = 'SHA-384'

    def __init__(self, cloudfront_id: str, priv_key_file: str) -> None:
        """Initializes `Signer` object.

        Args:
            cloudfront_id(str): the ID assigned to the public key in CloudFront
            priv_key_file(str): the path to the private PEM-formatted key
        """
        self.cloudfront_id: str = cloudfront_id
        if exists(priv_key_file):
            with open(priv_key_file, mode="rb") as priv_file:
                key_bytes = priv_file.read()
                self.priv_key = serialization.load_pem_private_key(key_bytes, password=None)
        else:
            raise PrivateKeyNotFound(f"{priv_key_file} not found")

    def _sign(self, policy: str) -> bytes:
        """Generate signature from policy and the private key associated
        with the public key in the CloudFront trusted key group.
        """
        signature: bytes = self.priv_key.sign(
            policy.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
        return signature
    
    def _validate_custom_policy(self):
        """Validates custom policy for signed cookie.

        Custom policy must match the following schema:
        {
			"Statement": [
				{
					"Resource": "URL of the file",
					"Condition": {
						"DateLessThan": {
							"AWS:EpochTime":required ending date and time in Unix time format and UTC
						},
						"DateGreaterThan": {
							"AWS:EpochTime":optional beginning date and time in Unix time format and UTC
						},
						"IpAddress": {
							"AWS:SourceIp": "optional IP address"
						}
					}
				}
			]
		} 
        """
        pass

    def _make_canned_policy(self, resource: str, expiration_date: int):
        """Returns default canned policy for signed cookies which only
        uses the `DataLessThan` condition.
        """
        policy = {
            'Statement': [
                {
                    'Resource': resource,
                    'Condition': {
                        'DateLessThan': {
                            'AWS:EpochTime': expiration_date
                        }
                    }
                }
            ]
        }
        return self._to_json(policy)

    def sanitize_b64(self, b64_str: str) -> str:
        """Removes invalid characters from final base64-encoded string.

        + -> -
        = -> _
        / -> ~
        """
        pass

    def _to_json(self, s: dict) -> str:
        """Converts dict to JSON string stripped of whitespaces."""
        return dumps(s).replace(" ", "")

    def generate_cookies(
        self,
        Resource: str="",
        Policy: dict={},
        SecondsBeforeExpires: int=900
    ) -> dict:
        """Generate and return signed cookies for accessing content behind CloudFront.

        Args:
            Resource(str): base URL for the resource you want to allow access to
            Policy(dict): custom policy statement for signed cookie
            SecondsBeforeExpires(int): numbers of seconds before cookie expires,
                default=900 (15 minutes)

        Returns:
            dict: returns dict containing the CloudFront-Policy, CloudFront-Signature,
                and CloudFront-Key-Pair-Id cookies
        """
        if Policy:
            policy: str = self._to_json(Policy)
        else:
            if not Resource:
                raise ValueError("must provide a resource URL")
            expires_on: datetime = datetime.now() + timedelta(seconds=SecondsBeforeExpires)
            policy: str = self._make_canned_policy(
                resource=Resource,
                expiration_date=int(expires_on.timestamp())
            )
        signature: bytes = self._sign(policy)

        cookies = {
            "CloudFront-Policy": b64encode(policy.encode("utf8")).decode(),
            "CloudFront-Signature": b64encode(signature).decode(),
            "CloudFront-Key-Pair-Id": self.cloudfront_id
        }

        return cookies

