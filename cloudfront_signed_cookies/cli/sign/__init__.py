import click
import logging

logging.basicConfig(level=logging.DEBUG)

from cloudfront_signed_cookies.signer import Signer
from json import loads


def create_curl_command(url: str, cookies: dict):
    print("curl --silent --header ", end="")
    cookies_str = f" --header ".join(
        [f"'Cookie: {k}={v}; Secure; HttpOnly'" for k, v in cookies.items()]
    )
    print(f"{cookies_str}", end=" ")
    print(f"--url '{url}'")


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--priv-key",
    "-p",
    "priv_key_file",
    type=str,
    required=True,
    help="the path to the private key file",
)
@click.option(
    "--key-id",
    "-k",
    required=True,
    help="the ID assigned to the public key uploaded to CloudFront",
)
@click.option(
    "--resource", "-r", required=True, help="the URL for the resource to access"
)
@click.option("--policy", "-l", help="the access control policy for the signed cookies")
@click.option(
    "--expires",
    "-e",
    default=900,
    help="[optional] numbers of seconds before the URL expires",
)
@click.pass_context
def sign(
    ctx: click.Context,
    priv_key_file: str,
    key_id: str,
    resource: str,
    policy,
    expires: int,
) -> None:
    if ctx.obj["DEBUG"]:
        logging.debug(
            f"priv_key_file={priv_key_file},"
            f"key_id={key_id}, resource={resource}, policy={policy}, expires={expires}"
        )
    if policy:
        policy = loads(policy)
    else:
        policy = {}
    cookies = Signer(
        cloudfront_key_id=key_id, priv_key_file=priv_key_file
    ).generate_cookies(Resource=resource, Policy=policy, SecondsBeforeExpires=expires)
    create_curl_command(resource, cookies)
