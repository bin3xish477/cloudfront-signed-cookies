import pytest

from cloudfront_signed_cookies import Signer

def test_positive_signer_initialization():
    signer = Signer(
        priv_key="some key"
    )

def test_negative_signer_initialization():
    signer = Signer(
        priv_key="some key"
    )

