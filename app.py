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


# ---------- Models ----------
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


# ---------- GUVI-style invalid body ----------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={"status": "error", "message": "INVALID_REQUEST_BODY"},
    )


def unauthorized():
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "UNAUTHORIZED"},
    )


# ---------- Health ----------
@app.get("/")
def root():
    return {"status": "ok"}


# ---------- Main ----------
@app.post("/honeypot")
def honeypot(payload: HoneypotPayload, x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    if not API_KEY or x_api_key != API_KEY:
        return unauthorized()

    session_id = payload.sessionId
    msg_text = (payload.message.text or "").strip()
    history = payload.conversationHistory or []
    metadata = payload.metadata or {}

    state = load_session(session_id)

    # rebuild if render slept and memory cleared
    if is_fresh_state(state) and history:
        rebuild_from_history(state, [m.model_dump() for m in history], extract_all)

    # count turn per request
    state.turnCount = (state.turnCount or 0) + 1

    # extract current message intel
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

    # detect scam once
    if not state.scamDetected:
        det = detect_scam(msg_text, [m.model_dump() for m in history], metadata)
        state.scamDetected = det.get("scamDetected", False)
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # reply
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, [m.model_dump() for m in history], metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Okay. Can you share more details?"

    # callback when ready
    try_send_final_callback(state)

    save_session(state)
    return {"status": "success", "reply": reply}
