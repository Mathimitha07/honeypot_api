# callback_reporter.py
import requests

from config import CALLBACK_URL
from session_store import SessionState


def try_send_final_callback(state: SessionState) -> None:
    """
    Sends the mandatory GUVI final result callback ONCE per session.
    - Sends only when scamDetected is true AND should_complete() is true.
    - Marks completed=True only when callback succeeds (2xx).
    - Retries up to 3 times across turns (callbackFailures counter).
    """

    # Stop if already completed or too many failures
    if state.completed or state.callbackFailures >= 3:
        return

    # Only send when scam is confirmed and we are ready to finalize
    if not state.scamDetected or not state.should_complete():
        return

    # Missing callback URL = failure
    if not CALLBACK_URL:
        state.callbackFailures += 1
        return

    payload = state.build_callback_payload()

    try:
        resp = requests.post(
            CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=8,
        )

        if 200 <= resp.status_code < 300:
            state.completed = True
            state.stage = "EXIT"
        else:
            state.callbackFailures += 1

    except Exception:
        state.callbackFailures += 1
