import click
import logging

from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(level=logging.DEBUG)

@click.command(context_settings={"ignore_unknown_options": True})
@click.option("--key-size", "-s", default=2048)
@click.pass_context
def genkeys(ctx: click.Context, key_size: int) -> None:
    pass
