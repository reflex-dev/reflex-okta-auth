"""Reflex state for Okta authentication."""

import base64
import contextlib
import datetime
import hashlib
import os
import secrets
from urllib.parse import urlencode, urlparse

import httpx
import reflex as rx
from okta_jwt_verifier.jwt_verifier import BaseJWTVerifier

from .config import client_id, client_secret, okta_issuer_uri
from .funcs import POST_MESSAGE_AND_CLOSE_POPUP, WINDOW_OPEN
from .message_listener import WindowMessage
from .oidc import okta_issuer_endpoint
from .types import OktaUserInfo

AUTHORIZATION_CODE_ENDPOINT = os.environ.get(
    "OKTA_AUTHORIZATION_CODE_ENDPOINT", "/authorization-code/callback"
)
POPUP_LOGIN_ENDPOINT = os.environ.get(
    "OKTA_POPUP_LOGIN_ENDPOINT", "/reflex-okta-auth/popup-login"
)
POPUP_LOGOUT_ENDPOINT = os.environ.get(
    "OKTA_POPUP_LOGOUT_ENDPOINT", "/reflex-okta-auth/popup-logout"
)


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
    error_message: str
    is_iframed: bool = False
    from_popup: bool = False

    _redirect_to_url: str
    _app_state: str
    _code_verifier: str
    _requested_scopes: str = "openid email profile"

    async def _validate_tokens(self, expiration_only: bool = False) -> bool:
        if not self.access_token or not self.id_token:
            return False

        # Ensure token is not expired.
        jwt_verifier = BaseJWTVerifier(
            issuer=okta_issuer_uri(),
            client_id=client_id(),
            audience=okta_issuer_uri(),
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
                await okta_issuer_endpoint("userinfo_endpoint"),
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
            with contextlib.suppress(Exception):
                resp.raise_for_status()
                return OktaUserInfo(resp.json())
            return None

    def _redirect_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(
            path=AUTHORIZATION_CODE_ENDPOINT,
            query=None,
            fragment=None,
        ).geturl()

    def _index_uri(self) -> str:
        current_url = urlparse(self.router.url)
        return current_url._replace(path="/", query=None, fragment=None).geturl()

    @rx.event
    async def redirect_to_login_popup(self):
        """Open a small popup window to initiate the login flow.

        This is used when the app detects it's embedded and needs to open a
        dedicated popup for the authorization flow.
        """
        return rx.call_script(
            WINDOW_OPEN(POPUP_LOGIN_ENDPOINT, "login", "width=600,height=600")
        )

    @rx.event
    async def redirect_to_logout_popup(self):
        """Open a small popup window to initiate the logout flow."""
        self.access_token = self.id_token = ""
        return rx.call_script(
            WINDOW_OPEN(POPUP_LOGOUT_ENDPOINT, "logout", "width=600,height=600")
        )

    @rx.event
    def set_from_popup(self, from_popup: bool):
        """Set whether the current page was opened as a popup."""
        self.from_popup = from_popup

    @rx.event
    async def redirect_to_login(self):
        """Initiate the OAuth 2.0 authorization code flow with PKCE.

        This method generates the necessary state and code verifier for PKCE,
        constructs the authorization URL, and redirects the user to Okta's
        authorization endpoint.

        Returns:
            A redirect response to the Okta authorization endpoint.
        """
        if self.is_iframed:
            return type(self).redirect_to_login_popup()
        if await self._validate_tokens():
            return [
                self.post_auth_message(),
                rx.toast("You are logged in."),
            ]

        # store app state and code verifier in session
        self._app_state = secrets.token_urlsafe(64)
        self._code_verifier = secrets.token_urlsafe(64)
        self._redirect_to_url = self.router.url

        # calculate code challenge
        hashed = hashlib.sha256(self._code_verifier.encode("ascii")).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode("ascii").strip("=")

        # get request params
        query_params = {
            "client_id": client_id(),
            "redirect_uri": self._redirect_uri(),
            "scope": self._requested_scopes,
            "state": self._app_state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "response_mode": "query",
        }

        # build request_uri
        request_uri = f"{await okta_issuer_endpoint('authorization_endpoint')}?{urlencode(query_params)}"
        return rx.redirect(request_uri)

    @rx.event
    async def redirect_to_logout(self):
        """Initiate the OAuth 2.0 logout flow.

        This method generates a new state parameter, constructs the logout URL
        with the ID token hint, and redirects the user to Okta's logout endpoint.
        The user's tokens are cleared from local storage after the redirect.

        Returns:
            A redirect response to the Okta logout endpoint.
        """
        if self.is_iframed:
            return type(self).redirect_to_logout_popup()

        # store app state and code verifier in session
        self._app_state = secrets.token_urlsafe(64)

        # get request params
        query_params = {
            "id_token_hint": self.id_token,
            "state": self._app_state,
        }
        if not self.from_popup:
            query_params["post_logout_redirect_uri"] = self._index_uri()

        # build request_uri
        request_uri = f"{await okta_issuer_endpoint('end_session_endpoint')}?{urlencode(query_params)}"
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
        code = self.router.url.query_parameters.get("code")
        app_state = self.router.url.query_parameters.get("state")
        if app_state != self._app_state:
            self.error_message = "App state mismatch. Possible CSRF attack."
            return rx.toast.error("Authentication error")
        if not code:
            self.error_message = "No code provided in the callback."
            return rx.toast.error("Authentication error")
        query_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri(),
            "code_verifier": self._code_verifier,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                await okta_issuer_endpoint("token_endpoint"),
                headers=headers,
                data=query_params,
                auth=(client_id(), client_secret()),
            )
            exchange = resp.json()

        # Get tokens and validate
        if not exchange.get("token_type"):
            self.error_message = "Unsupported token type. Should be 'Bearer'."
            return rx.toast.error("Authentication error")
        await self._set_tokens(
            access_token=exchange["access_token"],
            id_token=exchange["id_token"],
        )

        return rx.redirect(self._redirect_to_url)

    async def _set_tokens(self, access_token: str, id_token: str):
        self.access_token = access_token
        self.id_token = id_token

        await self._validate_tokens()

    @rx.var
    def origin(self) -> str:
        """Return the app origin URL (used as postMessage target origin)."""
        return self._index_uri().rstrip("/")

    @rx.event
    def check_if_iframed(self):
        """Run a short client-side check to determine whether the page is iframed.

        The result is reported to `check_if_iframed_cb`.
        """
        return rx.call_function(
            """() => {
    try {
        return window.self !== window.top;
    } catch (e) {
        // This catch block handles potential security errors (Same-Origin Policy)
        // if the iframe content and the parent are from different origins.
        // In such cases, access to window.top might be restricted, implying it's in an iframe.
        return true;
    }
}""",
            callback=type(self).check_if_iframed_cb,
        )

    @rx.event
    def check_if_iframed_cb(self, is_iframed: bool):
        """Callback invoked with the iframe detection result.

        Args:
            is_iframed: True if the page is inside an iframe or cross-origin
                access prevented detection.
        """
        self.is_iframed = is_iframed

    @rx.event
    async def on_iframe_auth_success(self, event: WindowMessage):
        """Handle an authentication success message posted from a child window.

        The message payload is expected to include `access_token`, `id_token`,
        and an optional `nonce`. Tokens are stored via `_set_tokens`.
        """
        if event["data"].get("type") != "auth":
            return
        await self._set_tokens(
            access_token=event["data"].get("access_token"),
            id_token=event["data"].get("id_token"),
        )

    @rx.event
    def post_auth_message(self):
        """Post tokens back to the opening window and close the popup.

        This is called on the popup page when authentication has completed and
        the tokens are available in `self.access_token` / `self.id_token`.
        """
        payload = {
            "type": "auth",
            "access_token": self.access_token,
            "id_token": self.id_token,
        }
        return rx.call_script(POST_MESSAGE_AND_CLOSE_POPUP(payload, self.origin, 500))
