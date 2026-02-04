from fastapi import FastAPI, Header, HTTPException
from typing import Dict

from config import API_KEY
from session_store import load_session, save_session
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()


@app.post("/honeypot")
def honeypot(payload: Dict, x_api_key: str = Header(None)):
    # Auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Minimal schema validation (matches hackathon input format)
    if (
        "sessionId" not in payload
        or "message" not in payload
        or not isinstance(payload["message"], dict)
        or "text" not in payload["message"]
    ):
        raise HTTPException(status_code=400, detail="Invalid input format")

    session_id = payload["sessionId"]
    msg_text = payload["message"]["text"]
    history = payload.get("conversationHistory", [])
    metadata = payload.get("metadata", {})

    state = load_session(session_id)

    # 1) Extract intelligence from the incoming message
    extracted = extract_all(msg_text)

    # Merge unique extracted values into state
    for k in ["upiIds", "bankAccounts", "phishingLinks", "phoneNumbers"]:
        vals = extracted.get(k, [])
        if not vals:
            continue
        current = getattr(state, k, [])
        for v in vals:
            if v not in current:
                current.append(v)
        setattr(state, k, current)

    # Merge suspicious keywords
    for w in extracted.get("suspiciousKeywords", []):
        if w not in state.suspiciousKeywords:
            state.suspiciousKeywords.append(w)

    # 2) Detect scam intent (only once per session)
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = det.get("scamDetected", False)
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []):
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 3) Generate reply (agentic if scam)
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
        state.turnCount = updates.get("turnCount", state.turnCount)
    else:
        reply = "Sorry, I didn't understand. Can you explain?"

    # 4) Mandatory callback when engagement completes
    try_send_final_callback(state)

    save_session(state)

    # Strict output required by hackathon
    return {"status": "success", "reply": reply}
