import click

@click.command(context_setting={"ignore_unknown_options": True})
@click.option("--key-size", "-s", default=2048)
def genkeys(key_size: int) -> None:
    pass
