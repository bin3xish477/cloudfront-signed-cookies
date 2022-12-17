import click

from cloudfront_signed_cookies.cli.sign import sign
from cloudfront_signed_cookies.cli.genkeys import genkeys

@click.command(context_setting={"ignore_unknown_options": True})
def csc():
    pass

csc.add_command(sign)
csc.add_command(genkeys)

def main():
    return csc()
