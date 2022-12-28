class PrivateKeyNotFound(Exception):
    """Raised when private key file is not found"""

    pass


class InvalidPrivateKeyFormat(Exception):
    """Raised when the provided private key is not correctly formatted"""

    pass


class InvalidCustomPolicy(Exception):
    """Raised when custom policy dict does not contain valid keys/values"""

    pass


class InvalidCloudFrontKeyId(Exception):
    """Raised if CloudFront public Id is not a valid UUID str"""

    pass
