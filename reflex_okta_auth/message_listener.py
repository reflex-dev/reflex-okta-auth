"""Helpers for listening to postMessage events from the browser window.

This module exposes a lightweight Reflex component that embeds a small
frontend script to forward window.postMessage events into Reflex event
handlers. It defines a `WindowMessage` type and the `message_listener`
factory for creating the component.
"""

from typing import Any, TypedDict

import reflex as rx
from reflex.event import passthrough_event_spec


class WindowMessage(TypedDict):
    """Type describing a message forwarded from the browser.

    Attributes:
        origin: The origin string of the message sender.
        data: The payload sent in the message.
        timestamp: A numeric timestamp included by the sender (if any).
    """

    origin: str
    data: Any
    timestamp: float


class MessageListener(rx.Component):
    """Reflex component embedding a small JS listener for window.postMessage.

    Use the `message_listener` factory to instantiate the component. The
    component accepts `allowed_origin` to restrict messages and an `on_message`
    event handler that receives a `WindowMessage` payload.
    """

    library = "$/public" + rx.asset("messageListener.js", shared=True)

    tag = "MessageListener"

    allowed_origin: str | None = None
    on_message: rx.EventHandler[passthrough_event_spec(WindowMessage)]


message_listener = MessageListener.create
