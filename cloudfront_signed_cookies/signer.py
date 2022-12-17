from rsa import sign as sign_with_rsa

class Signer:
    def __init__(self, priv_key) -> None:
        self.priv_key = priv_key

    def sign(self) -> bytes:
        pass
