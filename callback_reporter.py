# callback_reporter.py
import requests
from config import CALLBACK_URL
from session_store import SessionState


def try_send_final_callback(state: SessionState) -> None:
    # Only attempt when ready
    if state.callbackFailures >= 3:
        return
    if not state.scamDetected:
        return
    if not state.should_complete():
        return
    if not CALLBACK_URL:
        state.callbackFailures += 1
        return

    payload = state.build_callback_payload()

    try:
        resp = requests.post(CALLBACK_URL, json=payload, timeout=8)
        if 200 <= resp.status_code < 300:
            # Mark completed only after success
            state.completed = True
            state.stage = "EXIT"
        else:
            state.callbackFailures += 1
    except Exception:
        state.callbackFailures += 1
