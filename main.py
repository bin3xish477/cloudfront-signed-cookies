from cloudfront_signed_cookies.signer import Signer

if __name__ == "__main__":
    signer = Signer(
        cloudfront_key_id="K36X4X2EO997HM",
        priv_key_file="./certs/private_key.pem",
    )

    cookies: dict = signer.generate_cookies(
        # Resource="https://s3.amazonaws.com/somefile.txt",
        # Policy={},
        Policy={
            "Statement": [
                {
                    "Resource": "some_url",
                    "Condition": {"DateLessThan": {"AWS:EpochTime": 1000}},
                }
            ]
        },
        SecondsBeforeExpires=3600,
    )
    print(cookies)
    # cookie_str = "; ".join([f"{k}: {v}" for k, v in cookies.items()])
    # print(f"Set-Cookie: {cookie_str}")
