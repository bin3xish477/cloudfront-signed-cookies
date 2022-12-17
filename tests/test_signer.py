import pytest

from cloudfront_signed_cookies.signer import Signer

signer: Signer = Signer(
    cloudfront_id="46858301-6fdb-4645-a522-d09b5dea27a5",
    priv_key_file="./certs/private_key.pem"
)

def test_generate_cookies():
    cookies: dict = signer.generate_cookies(
        Resource="https://s3.amazonaws.com/somefile.txt",
        Policy={},
        SecondsBeforeExpires=3600
    )

    assert cookies != {}

def test_private_key_file_not_exists():
    with pytest.raises(FileNotFoundError):
        signer: Signer = Signer(
            cloudfront_id="46858301-6fdb-4645-a522-d09b5dea27a5",
            priv_key_file="./certs/file_not_exits.pem"
        )

