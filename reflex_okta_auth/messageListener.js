import { useEffect } from "react";

export function MessageListener({ allowedOrigin, onMessage }) {
  useEffect(() => {
    window.addEventListener("message", (event) => {
      if (event.origin !== allowedOrigin) {
        return;
      }
      onMessage({
        origin: event.origin,
        data: event.data,
        timestamp: event.timeStamp,
      });
    });
    return () => {
      window.removeEventListener("message", onMessage);
    };
  }, [allowedOrigin, onMessage]);

  return null;
}
