import click

from cloudfront_signed_cookies.signer import Signer
from json import loads

def gen_curl_command(cookies: dict):
    pass

@click.command(context_setting={"ignore_unknown_options": True})
@click.option("--priv-key", "-p", type=str, require=True,
    help="the path to the private key file"
)
@click.option("--key-id", "-k", required=True,
    help="the ID assigned to the public key uploaded to CloudFront"
)
@click.option("--resource", "-r", required=True,
    help="the URL for the resource to access"
)
@click.option("--policy", "-p",
    help="the access control policy for the signed cookies"
)
@click.option("--expires", "-e", default=900,
    help="[optional] numbers of seconds before the URL expires"
)

def sign(priv_key_file: str, key_id: str, resource: str, policy: str, expires) -> None:
    signer = Signer(
        cloudfront_id=key_id,
        priv_key_file=priv_key_file
    )

    policy_dict = loads(policy)
    cookies = signer.generate_cookies(
        Resource=resource,
        Policy=policy_dict,
        SecondsBeforeExpires=expires
    )


