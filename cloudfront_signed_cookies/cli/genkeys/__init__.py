import click
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import rsa


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--key-size", "-s", default=2048, help="the key size in bits, default=2048"
)
def genkeys(key_size: int) -> None:
    with (
        open("private_key.pem", mode="wb") as priv_key_file,
        open("public_key.pem", mode="wb") as pub_key_file,
    ):
        priv_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )
        # writing private PEM-formatted key
        pub_key: rsa.RSAPublicKey = priv_key.public_key()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_key_file.write(priv_pem)
        print(f"==> Saved private key to 'private_key.pem'")
        # writing public PEM-formatted key
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_key_file.write(pub_pem)
        print(f"==> Saved public key to 'public_key.pem'")
