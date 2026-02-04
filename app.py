from fastapi import FastAPI, Header, HTTPException
from typing import Dict

from config import API_KEY, CALLBACK_URL
from session_store import load_session, save_session
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()

# Receives callback payload locally for testing (LOCAL ONLY)
_LAST_CALLBACK = None


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


# ---------------------------
# DEBUG ROUTES (LOCAL TESTING ONLY)
# ---------------------------

@app.get("/debug/session/{session_id}")
def debug_session(session_id: str, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
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


@app.post("/debug/extract")
def debug_extract(payload: Dict, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    text = payload.get("text", "")
    return extract_all(text)


@app.post("/mock_callback")
def mock_callback(payload: Dict):
    global _LAST_CALLBACK
    _LAST_CALLBACK = payload
    return {"ok": True}


@app.get("/mock_callback/latest")
def mock_callback_latest(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return _LAST_CALLBACK or {"ok": False, "reason": "No callback received yet"}


@app.get("/debug/callback_url")
def debug_callback_url(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"CALLBACK_URL": CALLBACK_URL}
