# app.py
from typing import Any, Dict, List, Optional

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
        content={
            "status": "error",
            "message": "UNAUTHORIZED",
            "errorCode": "E401",
        },
    )


# -------------------------
# Health check (Render)
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}


# -------------------------
# Main endpoint (GUVI compatible + tolerant)
# -------------------------
@app.post("/honeypot")
def honeypot(payload: Any = Body(None), x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    # -----------------
    # Auth
    # -----------------
    if not API_KEY or x_api_key != API_KEY:
        # Keep it strict: GUVI tester expects auth to work
        raise HTTPException(status_code=401, detail="Unauthorized")

    # -----------------
    # GUVI tester tolerance:
    # Sometimes a tester sends empty body / wrong JSON.
    # Never crash. Still return the required output shape.
    # -----------------
    if not isinstance(payload, dict):
        return {
            "status": "success",
            "reply": "I’m getting an error on my side. Can you resend the exact message text again?"
        }

    session_id = payload.get("sessionId")
    message = payload.get("message")
    message = message if isinstance(message, dict) else {}
    msg_text = (message.get("text") or "").strip()

    # conversationHistory can be missing / wrong type
    history_raw = payload.get("conversationHistory") or []
    history: List[Dict[str, Any]] = history_raw if isinstance(history_raw, list) else []

    metadata_raw = payload.get("metadata") or {}
    metadata: Dict[str, Any] = metadata_raw if isinstance(metadata_raw, dict) else {}

    # If required fields missing, still respond normally (do NOT output INVALID_REQUEST_BODY)
    if not session_id or not msg_text:
        return {
            "status": "success",
            "reply": "I didn’t receive the full message. Please resend the exact text you got."
        }

    # -----------------
    # Load state (in-memory)
    # -----------------
    state = load_session(session_id)

    # If server restarted / Render slept and memory is lost, rebuild from conversationHistory
    if is_fresh_state(state) and history:
        rebuild_from_history(state, history, extract_all)

    # ✅ Count turns HERE (one per incoming request/message)
    state.turnCount = (state.turnCount or 0) + 1

    # -----------------
    # 1) Extract intelligence from incoming message
    # -----------------
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

    # -----------------
    # 2) Detect scam intent (only once per session)
    # -----------------
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = bool(det.get("scamDetected", False))
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # -----------------
    # 3) Generate reply (agentic if scam)
    # -----------------
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
        # ✅ do NOT overwrite turnCount from agent_engine
    else:
        # Non-scam: keep bland and safe
        reply = "Okay. Can you explain what you need help with?"

    # -----------------
    # 4) Mandatory callback when engagement completes
    # -----------------
    try_send_final_callback(state)

    # Persist
    save_session(state)

    # Strict output required by hackathon
    return {"status": "success", "reply": reply}


# -------------------------
# Debug routes (DEV only)
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

    @app.post("/debug/extract")
    def debug_extract(payload: Dict[str, Any], x_api_key: Optional[str] = Header(None, alias="x-api-key")):
        if not API_KEY or x_api_key != API_KEY:
            return unauthorized()
        text = (payload.get("text") or "").strip()
        return extract_all(text)

    # Mock callback receiver for local/dev testing (protected)
    _LAST_CALLBACK: Optional[Dict[str, Any]] = None

    @app.post("/mock_callback")
    def mock_callback(payload: Dict[str, Any], x_api_key: Optional[str] = Header(None, alias="x-api-key")):
        if not API_KEY or x_api_key != API_KEY:
            return unauthorized()
        nonlocal_vars = {"ok": True}  # just to avoid global confusion in some linters
        global _LAST_CALLBACK
        _LAST_CALLBACK = payload
        return nonlocal_vars

    @app.get("/mock_callback/latest")
    def mock_callback_latest(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
        if not API_KEY or x_api_key != API_KEY:
            return unauthorized()
        return _LAST_CALLBACK or {"ok": False, "reason": "No callback received yet"}

    @app.get("/debug/callback_url")
    def debug_callback_url(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
        if not API_KEY or x_api_key != API_KEY:
            return unauthorized()
        return {"CALLBACK_URL": CALLBACK_URL}
