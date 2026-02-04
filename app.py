# app.py
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ConfigDict

from config import API_KEY, CALLBACK_URL, ENV
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback


app = FastAPI()


# -------------------------
# Models (strict where needed, flexible overall)
# -------------------------
class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sender: Optional[str] = None
    text: str
    timestamp: Optional[str] = None


class HoneypotPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# -------------------------
# Error handling to match GUVI-style tester expectations
# (Instead of raw FastAPI 422/400)
# -------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={
            "status": "error",
            "message": "INVALID_REQUEST_BODY",
            "errorCode": "E400",
        },
    )


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
# Main endpoint
# -------------------------
@app.post("/honeypot")
def honeypot(payload: HoneypotPayload, x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    # Auth
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    session_id = payload.sessionId
    msg_text = payload.message.text
    history = [m.model_dump() for m in (payload.conversationHistory or [])]
    metadata = payload.metadata or {}

    # Load state
    state = load_session(session_id)

    # If Render slept / restarted and memory is empty, rebuild from conversationHistory
    if is_fresh_state(state) and history:
        rebuild_from_history(state, history, extract_all)

    # Count turns (one per incoming request)
    state.turnCount = (state.turnCount or 0) + 1

    # 1) Extract intelligence from incoming message
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

    # 2) Detect scam intent (only once per session)
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = bool(det.get("scamDetected", False))
        state.scamType = det.get("scamType", "unknown") or "unknown"
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 3) Generate reply
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Sorry, I didn't understand. Can you explain?"

    # 4) Mandatory callback once engagement completes
    try_send_final_callback(state)

    save_session(state)

    # Output required by hackathon
    return {"status": "success", "reply": reply}


# -------------------------
# Debug routes (disable in production)
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
