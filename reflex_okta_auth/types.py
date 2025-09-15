"""TypedDicts for Okta authentication user info."""

from typing import TypedDict


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
