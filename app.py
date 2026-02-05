# app.py
from typing import List, Dict, Any, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ConfigDict

from config import API_KEY, CALLBACK_URL, ENV
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()


# -------------------------
# Pydantic models (this fixes GUVI INVALID_REQUEST_BODY)
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
# Health check
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}


# -------------------------
# Main endpoint (GUVI will call this)
# -------------------------
@app.post("/honeypot")
def honeypot(
    payload: HoneypotPayload,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    # Auth
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    session_id = payload.sessionId
    msg_text = (payload.message.text or "").strip()
    history = payload.conversationHistory or []
    metadata = payload.metadata or {}

    # Load state
    state = load_session(session_id)

    # If server restarted and memory is empty, rebuild from history
    if is_fresh_state(state) and history:
        # Convert Message models -> dicts for your rebuild function
        history_dicts = [m.model_dump() for m in history]
        rebuild_from_history(state, history_dicts, extract_all)

    # Count turn (1 per incoming request)
    state.turnCount = (state.turnCount or 0) + 1

    # Extract intelligence from incoming message
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

    # Detect scam intent (only once)
    if not state.scamDetected:
        # Convert Message models -> dicts for detector
        history_dicts = [m.model_dump() for m in history]
        det = detect_scam(msg_text, history_dicts, metadata)
        state.scamDetected = bool(det.get("scamDetected", False))
        state.scamType = det.get("scamType", "unknown")

        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # Agent reply
    if state.scamDetected:
        # Convert Message models -> dicts for agent
        history_dicts = [m.model_dump() for m in history]
        reply, updates = next_reply(state, msg_text, history_dicts, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Sorry, I didn’t understand. Can you explain?"

    # Callback when complete
    try_send_final_callback(state)

    # Save state
    save_session(state)

    # Required output format
    return {"status": "success", "reply": reply}


# -------------------------
# Debug routes (DEV only)
# -------------------------
if ENV != "prod":

    @app.post("/debug/extract")
    def debug_extract(
        payload: Dict[str, Any],
        x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    ):
        if not API_KEY or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized")
        text = (payload.get("text") or "").strip()
        return extract_all(text)

    @app.get("/debug/session/{session_id}")
    def debug_session(
        session_id: str,
        x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    ):
        if not API_KEY or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized")

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
