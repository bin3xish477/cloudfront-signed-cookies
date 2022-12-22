# cloudfront-signed-cookies

[![PyPI - Version](https://img.shields.io/pypi/v/cloudfront-signed-cookies.svg)](https://pypi.org/project/cloudfront-signed-cookies)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cloudfront-signed-cookies.svg)](https://pypi.org/project/cloudfront-signed-cookies)
[![Hatch project](https://img.shields.io/badge/%F0%9F%A5%9A-Hatch-4051b5.svg)](https://github.com/pypa/hatch)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

-----

**Table of Contents**

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

```console
pip install cloudfront-signed-cookies
```

## Usage

```python
from cloudfront_signed_cookies.signer import Signer

def main():
    signer: Signer = Signer(
        cloudfront_key_id="K36X4X2EO997HM",
        priv_key_file="./certs/private_key.pem",
    )

    cookies: dict = signer.generate_cookies(
        Policy={
            "Statement": [
                {
                    "Resource": "https://domain.com/somefile.txt",
                    "Condition": {
                        "DateLessThan": {
                            "AWS:EpochTime": 1000
                        }
                    },
                }
            ]
        },
        SecondsBeforeExpires=360,
    )
    print(cookies)

main()
"""
{'CloudFront-Policy': 'eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoic29tZV91cmwiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjEwMDB9fX1dfQ__', 'CloudFront-Signature': 'EZHxOEAhaKB3e-XUAGI5xJdDQaWKuW-h6m8c4UYcFBkaA3Fh4~DygZUcYCj-S-qtUdrl46i8vp4RuvtDz4sL9GEVGGDniZc8iDVDqHmfllMFK-90Ge-C9lQ-umsqm-IQzaFVDS3WMbi5iAsRDpdUGfAk43ergTMvjhd~xxpVCCHZxW8uBt11kAjEoqdbMm6eVC32F-QB2HJndN9mm4d~dizvW~XjVt69fA0YjY7-TiIVKAO5ajnDaBl17AsLolLfLYl6NGBJjadLjueMCWM2DP5lXYce8RF2qW02wg8bNmth3ykPoVHFT-tgIgetOcDFDCFSnTkXXhUy3mu2wPzdKQ__', 'CloudFront-Key-Pair-Id': K36X4X2EO997HM'}
"""
```

## License

`cloudfront-signed-cookies` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
