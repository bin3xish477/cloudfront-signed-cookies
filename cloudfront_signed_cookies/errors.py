class PrivateKeyNotFound(Exception):
    """Raised when private key file is not found"""
    pass

class InvalidCustomPolicy(Exception):
    """Raised when custom policy dict does not contain valid keys/values"""
    pass
