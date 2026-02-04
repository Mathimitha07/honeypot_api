import requests
from config import CALLBACK_URL
from session_store import SessionState

def try_send_final_callback(state: SessionState) -> None:
    if state.completed or state.callbackFailures >= 3:
        return
    if not state.scamDetected or not state.should_complete():
        return
    if not CALLBACK_URL:
        state.callbackFailures += 1
        return

    payload = state.build_callback_payload()
    try:
        resp = requests.post(CALLBACK_URL, json=payload, timeout=5)
        if 200 <= resp.status_code < 300:
            state.completed = True
        else:
            state.callbackFailures += 1
    except Exception:
        state.callbackFailures += 1
