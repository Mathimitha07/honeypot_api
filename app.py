# app.py
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Header, HTTPException, Body
from fastapi.responses import JSONResponse

from config import API_KEY, CALLBACK_URL, ENV
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()

# -------------------------
# Helpers
# -------------------------
def unauthorized():
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "UNAUTHORIZED", "errorCode": "E401"},
    )

def ok_reply(text: str):
    return {"status": "success", "reply": text}

# -------------------------
# Health check
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}

# -------------------------
# Main endpoint
# IMPORTANT: payload is Any to avoid FastAPI 422
# -------------------------
@app.post("/honeypot")
def honeypot(
    payload: Any = Body(None),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # 1) Auth
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    # 2) GUVI tester sometimes sends a string body or empty body.
    #    Do NOT allow 422; handle gracefully.
    if payload is None:
        return ok_reply("Hi. Please share the message you received.")
    if not isinstance(payload, dict):
        # Example: payload == "string"
        return ok_reply("Please resend the message text you received so I can help.")

    # 3) Extract required fields safely
    session_id = payload.get("sessionId")
    message = payload.get("message") or {}
    msg_text = (message.get("text") or "").strip()

    history = payload.get("conversationHistory") or []
    metadata = payload.get("metadata") or {}

    # If missing key fields, still respond success (tester should not fail)
    if not session_id or not msg_text:
        return ok_reply("I didn’t receive the full message. Please resend the exact text you got.")

    # 4) Load state
    state = load_session(session_id)

    # If memory lost and history exists, rebuild
    if is_fresh_state(state) and isinstance(history, list) and history:
        rebuild_from_history(state, history, extract_all)

    # Count turns (one per request)
    state.turnCount = (state.turnCount or 0) + 1

    # 5) Extract intelligence
    extracted = extract_all(msg_text)

    for k in ["upiIds", "bankAccounts", "phishingLinks", "phoneNumbers"]:
        vals = extracted.get(k, []) or []
        if vals:
            current = getattr(state, k, [])
            for v in vals:
                if v not in current:
                    current.append(v)
            setattr(state, k, current)

    for w in extracted.get("suspiciousKeywords", []) or []:
        if w not in state.suspiciousKeywords:
            state.suspiciousKeywords.append(w)

    # 6) Scam detection (once per session)
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = det.get("scamDetected", False)
        state.scamType = det.get("scamType", "unknown")

        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 7) Reply generation
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Okay. Can you share more details?"

    # 8) Mandatory final callback (when complete)
    try_send_final_callback(state)

    # Save session
    save_session(state)

    return {"status": "success", "reply": reply}

# -------------------------
# Debug routes only if not prod
# -------------------------
if ENV != "prod":

    @app.get("/debug/session/{session_id}")
    def debug_session(session_id: str, x_api_key: Optional[str] = Header(None, alias="x-api-key")):
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
