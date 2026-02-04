import time
import requests
from config import CALLBACK_URL
from session_store import SessionState

def try_send_final_callback(state: SessionState) -> None:
    """
    Sends final result to CALLBACK_URL once the session meets completion criteria.
    - Attempts up to 3 failures.
    - Marks state.completed=True only on 2xx.
    - Logs useful info for Render debugging.
    """

    # If already done or too many failures, stop
    if state.completed or state.callbackFailures >= 3:
        return

    # Only send for scams and only when completion rule says so
    if not state.scamDetected or not state.should_complete():
        return

    # Must have a callback url
    if not CALLBACK_URL:
        state.callbackFailures += 1
        print("[CALLBACK] Missing CALLBACK_URL. failures=", state.callbackFailures)
        return

    payload = state.build_callback_payload()

    try:
        t0 = time.time()
        resp = requests.post(CALLBACK_URL, json=payload, timeout=10)
        ms = int((time.time() - t0) * 1000)

        # Log result (Render logs will show this)
        print(
            f"[CALLBACK] POST {CALLBACK_URL} "
            f"sessionId={state.sessionId} "
            f"status={resp.status_code} "
            f"latencyMs={ms}"
        )

        # If success, mark completed
        if 200 <= resp.status_code < 300:
            state.completed = True
            print(f"[CALLBACK] ✅ Success. sessionId={state.sessionId} marked completed=True")
        else:
            state.callbackFailures += 1
            # Log small snippet of response body to help debug (keep it short)
            body_snip = (resp.text or "")[:200].replace("\n", " ")
            print(
                f"[CALLBACK] ❌ Non-2xx. failures={state.callbackFailures} "
                f"body='{body_snip}'"
            )

    except Exception as e:
        state.callbackFailures += 1
        print(
            f"[CALLBACK] ❌ Exception. sessionId={state.sessionId} "
            f"failures={state.callbackFailures} error={repr(e)}"
        )
