# callback_reporter.py
import requests
from config import CALLBACK_URL
from session_store import SessionState


def try_send_final_callback(state: SessionState) -> None:
    # Stop retrying if already reported successfully or too many failures
    if state.completed or state.callbackFailures >= 3:
        return

    # Only callback for scam sessions, and only after enough engagement
    if not state.scamDetected or not state.should_complete():
        return

    # ✅ FIX: If the session is logically complete, lock stage to EXIT
    # (Do NOT mark completed=True until callback succeeds)
    state.stage = "EXIT"

    # If callback URL is missing, count failure and exit
    if not CALLBACK_URL:
        state.callbackFailures += 1
        return

    payload = state.build_callback_payload()

    try:
        resp = requests.post(CALLBACK_URL, json=payload, timeout=8)

        if 200 <= resp.status_code < 300:
            # ✅ Callback success: now we can mark completed
            state.completed = True
            state.stage = "EXIT"
        else:
            state.callbackFailures += 1

    except Exception:
        state.callbackFailures += 1
        # Keep stage EXIT; still allow retries in future turns
        state.stage = "EXIT"
