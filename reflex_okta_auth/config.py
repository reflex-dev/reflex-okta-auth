"""Configuration helpers for Okta authentication."""

import os


def client_id() -> str:
    """Get the Okta client ID from environment variables.

    Returns:
        The Okta client ID from the OKTA_CLIENT_ID environment variable,
        or an empty string if not set.
    """
    return os.environ.get("OKTA_CLIENT_ID", "")


def client_secret() -> str:
    """Get the Okta client secret from environment variables.

    Returns:
        The Okta client secret from the OKTA_CLIENT_SECRET environment variable,
        or an empty string if not set.
    """
    return os.environ.get("OKTA_CLIENT_SECRET", "")


def okta_issuer_uri() -> str:
    """Get the Okta issuer URI from environment variables.

    Returns:
        The Okta issuer URI from the OKTA_ISSUER_URI environment variable.

    Raises:
        RuntimeError: If the OKTA_ISSUER_URI environment variable is not set.
    """
    okta_issuer_uri = os.environ.get("OKTA_ISSUER_URI")
    if not okta_issuer_uri:
        raise RuntimeError("OKTA_ISSUER_URI environment variable is not set.")
    return okta_issuer_uri
