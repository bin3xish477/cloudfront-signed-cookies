import click

from cloudfront_signed_cookies.cli.sign import sign
from cloudfront_signed_cookies.cli.genkeys import genkeys


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.option("--debug/--no-debug", default=False)
@click.pass_context
def csc(ctx: click.Context, debug: bool):
    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug


csc.add_command(sign)
csc.add_command(genkeys)


def main():
    return csc(obj={})
