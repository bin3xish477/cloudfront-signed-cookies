import pytest
from datetime import datetime
from cloudfront_signed_cookies.signer import Signer
from cloudfront_signed_cookies.errors import (
    InvalidCustomPolicy,
    PrivateKeyNotFound,
    InvalidCloudFrontKeyId,
)

signer: Signer = Signer(
    cloudfront_key_id="K36X4X2EO997HM",
    priv_key_file="./certs/private_key.pem",
)


def test_generate_cookies():
    cookies: dict = signer.generate_cookies(
        Resource="https://s3.amazonaws.com/somefile.txt",
        Policy={},
        SecondsBeforeExpires=3600,
    )
    assert cookies != {}


def test_private_key_file_not_exists():
    with pytest.raises(PrivateKeyNotFound):
        Signer(
            cloudfront_key_id="K2K0M437QMM888",
            priv_key_file="./certs/file_not_exits.pem",
        )


def test_generated_cookies_with_custom_policy():
    signer.generate_cookies(
        Policy={
            "Statement": [
                {
                    "Resource": "https://example.com/somefile.txt",
                    "Condition": {
                        "DateLessThan": {
                            "AWS:EpochTime": int(datetime.now().timestamp())
                        },
                        "IpAddress": {"AWS:SourceIp": "10.10.10.0/24"},
                    },
                }
            ]
        },
        SecondsBeforeExpires=600,
    )


def test_custom_policy_for_missing_statement():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={"InvalidKey": []},
            SecondsBeforeExpires=600,
        )


def test_for_empty_resource_with_custom_policy():
    with pytest.raises(ValueError):
        signer.generate_cookies(
            SecondsBeforeExpires=600,
        )


def test_custom_policy_for_incorrect_resource_type():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={"Statement": [{"Resource": 1, "Condition": {}}]},
            SecondsBeforeExpires=600,
        )


def test_custom_policy_for_missing_conditions():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={"Statement": [{"Resource": "URL"}]},
            SecondsBeforeExpires=600,
        )


def test_custom_policy_for_invalid_keys():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={
                "Statement": [{"Resource": "URL", "Condition": {"InvalidKey": "value"}}]
            },
            SecondsBeforeExpires=600,
        )


def test_custom_policy_for_invalid_subkeys():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={
                "Statement": [
                    {
                        "Resource": "URL",
                        "Condition": {"DateLessThan": {"InvalidSubKey": 1000}},
                    }
                ]
            },
            SecondsBeforeExpires=600,
        )


def test_custom_policy_for_invalid_subkey_types():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={
                "Statement": [
                    {
                        "Resource": "URL",
                        "Condition": {"DateLessThan": {"AWS:EpochTime": "not_an_int"}},
                    }
                ]
            },
            SecondsBeforeExpires=600,
        )


def test_for_invalid_cloudfront_key_id():
    with pytest.raises(InvalidCloudFrontKeyId):
        Signer(
            cloudfront_key_id="134041ajfdfadffljfdsg00",
            priv_key_file="./certs/private_key.pem",
        )


def test_for_invalid_custom_policy_date_range():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={
                "Statement": [
                    {
                        "Resource": "URL",
                        "Condition": {
                            "DateLessThan": {"AWS:EpochTime": 10010},
                            "DateGreaterThan": {"AWS:EpochTime": 10020},
                        },
                    }
                ]
            },
            SecondsBeforeExpires=600,
        )


def test_for_missing_expiration_date_condition_key():
    with pytest.raises(InvalidCustomPolicy):
        signer.generate_cookies(
            Policy={
                "Statement": [
                    {
                        "Resource": "URL",
                        "Condition": {
                            "DateGreaterThan": {"AWS:EpochTime": 1000},
                        },
                    }
                ]
            },
            SecondsBeforeExpires=600,
        )
