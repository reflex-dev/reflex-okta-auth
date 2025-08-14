# reflex-okta-auth

This package requires the `reflex_enterprise` package to be installed.

## Installation

```bash
pip install reflex-okta-auth
```

## Usage

### Set Up Okta Application

Create a new Application and set up a .env file with the following variables:

```env
OKTA_CLIENT_ID=your_client_id
OKTA_CLIENT_SECRET=your_client_secret
OKTA_ISSUER_URI=your oauth issuer uri
```

Reflex will need to access these variables to authenticate users.

### Register Auth Callback

```python
from reflex_enterprise import App
from reflex_okta_auth import register_auth_endpoints

...

app = App()
register_auth_endpoints(app)
```

### Check `OktaAuthState.userinfo` for user identity/validity

```python
import reflex as rx
from reflex_okta_auth import OktaAuthState

@rx.page()
def index():
    return rx.container(
        rx.vstack(
            rx.heading("Okta Auth Demo"),
            rx.cond(
                rx.State.is_hydrated,
                rx.cond(
                    OktaAuthState.userinfo,
                    rx.vstack(
                        rx.text(f"Welcome, {OktaAuthState.userinfo["name"]}!"),
                        rx.text(OktaAuthState.userinfo.to_string()),
                        rx.button("Logout", on_click=OktaAuthState.redirect_to_logout),
                    ),
                    rx.button("Log In with Okta", on_click=OktaAuthState.redirect_to_login),
                ),
                rx.spinner(),
            ),
        ),
    )
```

### Validate the Tokens

Before performing privileged backend operations, it is important to validate the
tokens to ensure they have not been tampered with. Use
`OktaAuthState._validate_tokens()` helper method to validate the tokens.
