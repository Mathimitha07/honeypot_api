from fastapi import FastAPI, Header, HTTPException
from typing import Dict

from config import API_KEY, CALLBACK_URL
from session_store import load_session, save_session, is_fresh_state, rebuild_from_history
from detector import detect_scam
from extractor import extract_all
from agent_engine import next_reply
from callback_reporter import try_send_final_callback

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/honeypot")
def honeypot(payload: Dict, x_api_key: str = Header(None)):
    # Auth
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Validate input
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
    if history is None or not isinstance(history, list):
        history = []

    metadata = payload.get("metadata", {})
    if metadata is None or not isinstance(metadata, dict):
        metadata = {}

    # Load state
    state = load_session(session_id)

    # If memory is fresh but we have history, rebuild (Render restart/sleep)
    if is_fresh_state(state) and history:
        rebuild_from_history(state, history, extract_all)

    # Count turn (one per incoming request)
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

    # 2) Detect scam intent (only once)
    if not state.scamDetected:
        det = detect_scam(msg_text, history, metadata)
        state.scamDetected = det.get("scamDetected", False)
        state.scamType = det.get("scamType", "unknown")
        for kw in det.get("keywords", []) or []:
            if kw not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(kw)

    # 3) Generate reply
    if state.scamDetected:
        reply, updates = next_reply(state, msg_text, history, metadata)
        state.stage = updates.get("stage", state.stage)
    else:
        reply = "Sorry, I didn't understand. Can you explain?"

    # 4) Mandatory callback (when should_complete becomes true)
    try_send_final_callback(state)

    save_session(state)

    return {"status": "success", "reply": reply}


# ---------------------------
# DEBUG ROUTES (Protected)
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


@app.get("/debug/callback_url")
def debug_callback_url(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"CALLBACK_URL": CALLBACK_URL}


# ---------------------------
# MOCK CALLBACK (Protected)
# ---------------------------
_LAST_CALLBACK = None


@app.post("/mock_callback")
def mock_callback(payload: Dict, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    global _LAST_CALLBACK
    _LAST_CALLBACK = payload
    return {"ok": True}


@app.get("/mock_callback/latest")
def mock_callback_latest(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return _LAST_CALLBACK or {"ok": False, "reason": "No callback received yet"}
