"""OIDC helpers."""

import httpx

from .config import okta_issuer_uri

# Simple cached OIDC metadata + JWKS loader
_OIDC_CACHE: dict[str, dict] = {}


async def _fetch_oidc_metadata(issuer: str) -> dict:
    key = f"metadata:{issuer}"
    if key in _OIDC_CACHE:
        return _OIDC_CACHE[key]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)
        resp.raise_for_status()
        md = resp.json()
        _OIDC_CACHE[key] = md
        return md


async def okta_issuer_endpoint(service: str) -> str:
    """Fetch an endpoint URL (authorization/token/userinfo/etc) from OIDC metadata."""
    return (await _fetch_oidc_metadata(okta_issuer_uri()))[service]
