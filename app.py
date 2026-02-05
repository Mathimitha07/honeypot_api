# app.py
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from config import API_KEY, CALLBACK_URL, ENV
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()


# -------------------------
# Helpers (GUVI-friendly responses)
# -------------------------
def ok_reply(text: str) -> Dict[str, str]:
    return {"status": "success", "reply": text}


def invalid_request_body() -> JSONResponse:
    # GUVI tester likes this style
    return JSONResponse(
        status_code=200,
        content={"status": "success", "reply": "INVALID_REQUEST_BODY"},
    )


def unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "UNAUTHORIZED", "errorCode": "E401"},
    )


# -------------------------
# Health check
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}


# -------------------------
# Main honeypot endpoint
# -------------------------
@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # 1) Auth (must be header: x-api-key)
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    # 2) Parse body safely (NO 422)
    try:
        payload = await request.json()
    except Exception:
        return invalid_request_body()

    if not isinstance(payload, dict):
        return invalid_request_body()

    # 3) Read fields safely
    session_id = payload.get("sessionId")
    message = payload.get("message") or {}
    msg_text = (message.get("text") or "").strip()

    history = payload.get("conversationHistory") or []
    metadata = payload.get("metadata") or {}

    # If GUVI sends incomplete body, don't crash or 400
    if not session_id or not msg_text:
        return ok_reply("Please resend the message text (content missing).")

    # 4) Load session
    state = load_session(session_id)

    # If server restarted and GUVI sends conversationHistory, rebuild state
    if is_fresh_state(state) and isinstance(history, list) and history:
        rebuild_from_history(state, history, extract_all)

    # 5) Count turns (one per incoming request)
    state.turnCount = (state.turnCount or 0) + 1

    # 6) Extract intelligence from incoming message
    extracted = extract_all(msg_text)

    for k in ["upiIds", "bankAccounts", "phishingLinks", "phoneNumbers"]:
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

    # 7) Detect scam intent (only once per session)
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = bool(det.get("scamDetected", False))
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 8) Agent reply
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Okay. Can you share more details?"

    # 9) Mandatory callback when ready
    try_send_final_callback(state)

    # 10) Save state
    save_session(state)

    return ok_reply(reply)


# -------------------------
# Debug routes (disable in prod)
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
                "suspiciousKeywords": state.suspiciousKeywords,
            },
        }
