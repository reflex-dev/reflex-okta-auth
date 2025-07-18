"""Welcome to Reflex! This file outlines the steps to create a basic app."""

import reflex as rx
import reflex_enterprise as rxe

from reflex_okta_auth import OktaAuthState, register_auth_endpoints


def index():
    return rx.container(
        rx.vstack(
            rx.heading("Okta Auth Demo"),
            rx.cond(
                rx.State.is_hydrated,
                rx.cond(
                    OktaAuthState.userinfo,
                    rx.vstack(
                        rx.text(f"Welcome, {OktaAuthState.userinfo['name']}!"),
                        rx.text(OktaAuthState.userinfo.to_string()),
                        rx.button("Logout", on_click=OktaAuthState.redirect_to_logout),
                    ),
                    rx.button(
                        "Log In with Okta", on_click=OktaAuthState.redirect_to_login
                    ),
                ),
                rx.spinner(),
            ),
        ),
    )


app = rxe.App()
app.add_page(index, title="Okta Auth Demo")
register_auth_endpoints(app)
