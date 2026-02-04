# app.py
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request
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
# Models
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
# Error handling (GUVI-style)
# -------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # GUVI tester expects this exact style
    return JSONResponse(
        status_code=200,
        content={"status": "error", "message": "INVALID_REQUEST_BODY", "errorCode": "E400"},
    )


def unauthorized():
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
# Main endpoint
# -------------------------
@app.post("/honeypot")
def honeypot(
    payload: HoneypotPayload,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # Auth
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    session_id = payload.sessionId
    msg_text = (payload.message.text or "").strip()
    history = payload.conversationHistory or []
    metadata = payload.metadata or {}

    # Load state
    state = load_session(session_id)

    # Rebuild after Render sleep/restart
    if is_fresh_state(state) and history:
        # Convert Message objects -> dicts
        history_dicts = [m.model_dump() for m in history]
        rebuild_from_history(state, history_dicts, extract_all)

    # Count turns (one per incoming request)
    state.turnCount = (state.turnCount or 0) + 1

    # Extract intelligence from incoming message
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

    # Detect scam intent once
    if not state.scamDetected:
        # Convert history to dicts for detector
        history_dicts = [m.model_dump() for m in history]
        det = detect_scam(msg_text, history_dicts, metadata)
        state.scamDetected = det.get("scamDetected", False)
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # Generate reply
    if state.scamDetected:
        # Convert history to dicts for agent
        history_dicts = [m.model_dump() for m in history]
        reply, updates = next_reply(state, msg_text, history_dicts, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Okay. Can you share more details?"

    # Mandatory callback
    try_send_final_callback(state)

    # Save state
    save_session(state)

    return {"status": "success", "reply": reply}


# -------------------------
# Debug routes only in dev
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
