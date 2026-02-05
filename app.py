# app.py
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from config import API_KEY, CALLBACK_URL, ENV
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()


def ok_reply(text: str) -> Dict[str, str]:
    return {"status": "success", "reply": text}


def invalid_request_body() -> JSONResponse:
    return JSONResponse(status_code=200, content=ok_reply("INVALID_REQUEST_BODY"))


def unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "UNAUTHORIZED", "errorCode": "E401"},
    )


def _fingerprint_message(msg: Dict[str, Any]) -> str:
    """
    Make a stable fingerprint for dedupe.
    GUVI may resend the same event; we must ignore duplicates.
    """
    sender = (msg.get("sender") or "").strip().lower()
    text = (msg.get("text") or "").strip()
    ts = (msg.get("timestamp") or "").strip()
    return f"{sender}|{ts}|{text}"


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # 1) Auth
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    # 2) Parse JSON safely (avoid FastAPI 422)
    try:
        payload = await request.json()
    except Exception:
        return invalid_request_body()

    if not isinstance(payload, dict):
        return invalid_request_body()

    # 3) Read fields safely
    session_id = payload.get("sessionId")
    message = payload.get("message") or {}
    history = payload.get("conversationHistory") or []
    metadata = payload.get("metadata") or {}

    msg_text = (message.get("text") or "").strip()

    # If GUVI sends incomplete body, respond gracefully
    if not session_id or not msg_text:
        return ok_reply("Please resend the message text (content missing).")

    # 4) Load session
    state = load_session(session_id)

    # 5) Rebuild after restart if history exists
    if is_fresh_state(state) and isinstance(history, list) and history:
        rebuild_from_history(state, history, extract_all)

    # 6) Dedupe repeated event (do NOT increment turnCount or re-extract)
    fp = _fingerprint_message(message)
    if fp and fp in state.seenFingerprints:
        # Return a safe neutral reply (do not change state)
        return ok_reply("Okay. Please share the next step.")

    if fp:
        state.seenFingerprints.add(fp)

    # 7) Count turns (incoming requests only, after dedupe)
    state.turnCount = (state.turnCount or 0) + 1

    # 8) Extract intel from CURRENT incoming message only
    extracted = extract_all(msg_text)

    # Merge extracted lists uniquely into state
    for k in [
        "upiIds",
        "bankAccounts",
        "phishingLinks",
        "phoneNumbers",
        "ifscCodes",
        "beneficiaryNames",
    ]:
        vals = extracted.get(k, []) or []
        if not vals:
            continue
        current = getattr(state, k, [])
        for v in vals:
            if v not in current:
                current.append(v)
        setattr(state, k, current)

    for w in extracted.get("suspiciousKeywords", []) or []:
        if w not in state.suspiciousKeywords:
            state.suspiciousKeywords.append(w)

    # 9) Detect scam intent once per session
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = bool(det.get("scamDetected", False))
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 10) Agent reply
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Okay. Can you share more details?"

    # 11) Mandatory callback when ready
    # Use GUVI-style "both sides" total for callback payload
    history_len = len(history) if isinstance(history, list) else 0
    state.lastHistoryLen = history_len
    try_send_final_callback(state)

    # 12) Save
    save_session(state)

    return ok_reply(reply)


# -------------------------
# Debug routes (dev only)
# -------------------------
if ENV != "prod":

    @app.get("/debug/session/{session_id}")
    def debug_session(
        session_id: str,
        x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    ):
        if not API_KEY or x_api_key != API_KEY:
            return unauthorized()

        state = load_session(session_id)
        return {
            "sessionId": state.sessionId,
            "scamDetected": state.scamDetected,
            "scamType": state.scamType,
            "stage": state.stage,
            "turnCount": state.turnCount,
            "completed": state.completed,
            "callbackFailures": state.callbackFailures,
            "callbackUrlUsed": CALLBACK_URL,
            "extractedIntelligence": {
                "upiIds": state.upiIds,
                "bankAccounts": state.bankAccounts,
                "phishingLinks": state.phishingLinks,
                "phoneNumbers": state.phoneNumbers,
                "ifscCodes": state.ifscCodes,
                "beneficiaryNames": state.beneficiaryNames,
                "suspiciousKeywords": state.suspiciousKeywords,
            },
        }
