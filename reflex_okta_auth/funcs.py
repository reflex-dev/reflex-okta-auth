"""Javascript functions for working with the browser."""

from reflex.vars import Var
from reflex.vars.function import ArgsFunctionOperation, FunctionStringVar

WINDOW_OPEN = FunctionStringVar.create("window.open")
POST_MESSAGE_AND_CLOSE_POPUP = ArgsFunctionOperation.create(
    ("payload", "origin", "close_timeout"),
    return_expr=Var("""{
        if (window.opener && window.opener.origin === origin) {
            window.opener.postMessage(payload, origin);
            setTimeout(() => window.close(), close_timeout);
        }
    }"""),
)
