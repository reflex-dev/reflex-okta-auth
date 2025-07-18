"""Integrate Okta authentication with Reflex applications."""

import base64
import contextlib
import datetime
import hashlib
import os
import secrets
from collections.abc import Callable
from typing import TypedDict
from urllib.parse import urlencode, urljoin, urlparse

import httpx
import reflex as rx
from okta_jwt_verifier import BaseJWTVerifier
from reflex_enterprise import App


def okta_issuer_endpoint(service: str | None = None, version: str = "v1") -> str:
    """Construct an Okta issuer endpoint URL for a given service.

    Args:
        service: The Okta service endpoint (e.g., 'authorize', 'token', 'userinfo', 'logout').
                If None, returns the base issuer URI.
        version: The API version to use. Defaults to "v1".

    Returns:
        The complete URL for the specified Okta service endpoint.

    Raises:
        RuntimeError: If the OKTA_ISSUER_URI environment variable is not set.

    Example:
        >>> okta_issuer_endpoint("authorize")
        "https://dev-12345.okta.com/oauth2/default/v1/authorize"
    """
    okta_issuer_uri = os.environ.get("OKTA_ISSUER_URI")
    if not okta_issuer_uri:
        raise RuntimeError("OKTA_ISSUER_URI environment variable is not set.")
    if service is None:
        return okta_issuer_uri
    return urljoin(
        okta_issuer_uri,
        "/".join([version, service]),
    )


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


def audience() -> str:
    """Get the Okta audience from environment variables.

    Returns:
        The Okta audience from the OKTA_AUDIENCE environment variable,
        or "api://default" if not set.
    """
    return os.environ.get("OKTA_AUDIENCE", "api://default")


class OktaUserInfo(TypedDict):
    """TypedDict representing user information from Okta.

    Contains user profile data returned by the Okta /userinfo endpoint
    following successful authentication.

    Attributes:
        sub: The unique user identifier (subject).
        email: The user's email address.
        name: The user's full name.
        given_name: The user's first name.
        middle_name: The user's middle name.
        family_name: The user's last name/surname.
        nickname: The user's nickname.
        preferred_username: The user's preferred username.
        gender: The user's gender.
        profile: URL to the user's profile page.
        picture: URL to the user's profile picture.
        website: URL to the user's website.
        birthdate: The user's birthdate (ISO 8601 format).
        locale: The user's locale preference.
        zoneinfo: The user's timezone.
        email_verified: Whether the user's email has been verified.
        updated_at: Timestamp of last profile update (Unix epoch).
    """

    sub: str
    email: str | None
    name: str | None
    given_name: str | None
    middle_name: str | None
    family_name: str | None
    nickname: str | None
    preferred_username: str | None
    gender: str | None
    profile: str | None
    picture: str | None
    website: str | None
    birthdate: str | None
    locale: str | None
    zoneinfo: str | None
    email_verified: bool | None
    updated_at: int | None


class OktaAuthState(rx.State):
    """Reflex state class for managing Okta authentication.

    This state class handles the OAuth 2.0 Authorization Code flow with PKCE
    for Okta authentication, including token storage, validation, and user
    information retrieval.

    Attributes:
        access_token: The OAuth 2.0 access token stored in local storage.
        id_token: The OpenID Connect ID token stored in local storage.
        app_state: Random state parameter for CSRF protection.
        code_verifier: PKCE code verifier for secure authorization.
        redirect_to_url: URL to redirect to after successful authentication.
        error_message: Error message for authentication failures.
    """

    access_token: str = rx.LocalStorage()
    id_token: str = rx.LocalStorage()

    app_state: str
    code_verifier: str
    redirect_to_url: str
    error_message: str

    _requested_scopes: str = "openid email profile"

    async def _validate_tokens(self, expiration_only: bool = False) -> bool:
        if not self.access_token or not self.id_token:
            return False

        # Ensure token is not expired.
        jwt_verifier = BaseJWTVerifier(
            issuer=okta_issuer_endpoint(),
            client_id=client_id(),
            audience=audience(),
        )
        try:
            jwt_verifier.verify_expiration(self.access_token)
            jwt_verifier.verify_expiration(self.id_token)
        except Exception as e:
            print(f"Token validation failed: {e}")  # noqa: T201
            return False

        if expiration_only:
            return True

        try:
            await jwt_verifier.verify_access_token(self.access_token)
        except Exception as e:
            print(f"Access token verification failed: {e}")  # noqa: T201
            return False

        try:
            await jwt_verifier.verify_id_token(self.id_token)
        except Exception as e:
            print(f"ID token verification failed: {e}")  # noqa: T201
            return False

        return True

    @rx.var(interval=datetime.timedelta(minutes=30))
    async def userinfo(self) -> OktaUserInfo | None:
        """Get the authenticated user's information from Okta.

        This property retrieves the user's profile information from the Okta
        userinfo endpoint using the stored access token. The result is cached
        for 30 minutes and automatically revalidated.

        Returns:
            OktaUserInfo containing user profile data if authentication is valid,
            None if tokens are invalid or the request fails.
        """
        if not await self._validate_tokens(expiration_only=True):
            return None

        # Get the latest userinfo
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                okta_issuer_endpoint("userinfo"),
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            with contextlib.suppress(Exception):
                resp.raise_for_status()
                return OktaUserInfo(resp.json())
            return None

    def _redirect_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(
            path="/authorization-code/callback", query=None, fragment=None
        ).geturl()

    def _index_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(path="/", query=None, fragment=None).geturl()

    @rx.event
    def redirect_to_login(self):
        """Initiate the OAuth 2.0 authorization code flow with PKCE.

        This method generates the necessary state and code verifier for PKCE,
        constructs the authorization URL, and redirects the user to Okta's
        authorization endpoint.

        Returns:
            A redirect response to the Okta authorization endpoint.
        """
        # store app state and code verifier in session
        self.app_state = secrets.token_urlsafe(64)
        self.code_verifier = secrets.token_urlsafe(64)
        self.redirect_to_url = self.router.url

        # calculate code challenge
        hashed = hashlib.sha256(self.code_verifier.encode("ascii")).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode("ascii").strip("=")

        # get request params
        query_params = {
            "client_id": client_id(),
            "redirect_uri": self._redirect_uri(),
            "scope": "openid email profile",
            "state": self.app_state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "response_mode": "query",
        }

        # build request_uri
        request_uri = f"{okta_issuer_endpoint('authorize')}?{urlencode(query_params)}"
        return rx.redirect(request_uri)

    @rx.event
    def redirect_to_logout(self):
        """Initiate the OAuth 2.0 logout flow.

        This method generates a new state parameter, constructs the logout URL
        with the ID token hint, and redirects the user to Okta's logout endpoint.
        The user's tokens are cleared from local storage after the redirect.

        Returns:
            A redirect response to the Okta logout endpoint.
        """
        # store app state and code verifier in session
        self.app_state = secrets.token_urlsafe(64)

        # get request params
        query_params = {
            "id_token_hint": self.id_token,
            "post_logout_redirect_uri": self._index_uri(),
            "state": self.app_state,
        }

        # build request_uri
        request_uri = f"{okta_issuer_endpoint('logout')}?{urlencode(query_params)}"
        self.reset()
        return rx.redirect(request_uri)

    @rx.event
    async def auth_callback(self):
        """Handle the OAuth 2.0 authorization callback from Okta.

        This method is called when the user is redirected back from Okta's
        authorization endpoint. It validates the state parameter to prevent CSRF
        attacks, exchanges the authorization code for tokens using PKCE, and
        stores the tokens for future use.

        Returns:
            A redirect response to the original requested URL, or an error toast
            if authentication fails.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        code = self.router.page.params.get("code")
        app_state = self.router.page.params.get("state")
        if app_state != self.app_state:
            self.error_message = "App state mismatch. Possible CSRF attack."
            return rx.toast.error("Authentication error")
        if not code:
            self.error_message = "No code provided in the callback."
            return rx.toast.error("Authentication error")
        query_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri(),
            "code_verifier": self.code_verifier,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                okta_issuer_endpoint("token"),
                headers=headers,
                data=query_params,
                auth=(client_id(), client_secret()),
            )
            exchange = resp.json()

        # Get tokens and validate
        if not exchange.get("token_type"):
            self.error_message = "Unsupported token type. Should be 'Bearer'."
            return rx.toast.error("Authentication error")
        self.access_token = exchange["access_token"]
        self.id_token = exchange["id_token"]

        return rx.redirect(self.redirect_to_url)


def _authentication_loading_page() -> rx.Component:
    return rx.container(
        rx.vstack(
            rx.cond(
                ~rx.State.is_hydrated | ~OktaAuthState.userinfo,
                rx.hstack(
                    rx.heading("Validating Authentication..."),
                    rx.spinner(),
                    width="50%",
                    justify="between",
                ),
                rx.heading("Redirecting to app..."),
            ),
        ),
    )


def register_auth_endpoints(
    app: App,
    loading_page: Callable[[], rx.Component] = _authentication_loading_page,
):
    """Register the Okta authentication endpoints with the Reflex app.

    This function sets up the necessary OAuth callback endpoint for handling
    authentication responses from Okta. The callback endpoint handles the
    authorization code exchange and redirects users appropriately.

    Args:
        app: The Reflex Enterprise app instance to register endpoints with.
        loading_page: A callable that returns a Reflex component to display
                     while authentication is being processed. Defaults to
                     the built-in loading page.

    Raises:
        ValueError: If the app does not have an API configured.
        TypeError: If the app is not an instance of reflex_enterprise.App.
    """
    if app._api is None:
        raise ValueError("The app must have an API to register auth endpoints.")
    if not isinstance(app, App):
        raise TypeError("The app must be an instance of reflex_enterprise.App.")
    app.add_page(
        loading_page,
        route="/authorization-code/callback",
        on_load=OktaAuthState.auth_callback,
        title="Okta Auth Callback",
    )
