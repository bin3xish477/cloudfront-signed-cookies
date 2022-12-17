import click

@click.command(context_setting={"ignore_unknown_options": True})
@click.option("--priv-key", "-p", type=click.File(), require=True)
@click.option("--key-id", "-k", required=True)
def sign(priv_key_file: click.File, key_id: str) -> None:
    pass
