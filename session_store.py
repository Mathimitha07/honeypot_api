# session_store.py
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Any
import time


@dataclass
class SessionState:
    sessionId: str
    scamDetected: bool = False
    scamType: str = "unknown"
    stage: str = "HOOK"  # HOOK / FRICTION / EXTRACT / VERIFY / EXIT
    turnCount: int = 0

    completed: bool = False
    callbackFailures: int = 0

    # Anti-loop counters / flags
    upiRepeatCount: int = 0
    linkRepeatCount: int = 0
    bankRepeatCount: int = 0

    askedBeneficiary: bool = False
    askedAlternate: bool = False
    askedIfsc: bool = False

    upiIds: List[str] = field(default_factory=list)
    bankAccounts: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)

    lastUpdated: float = field(default_factory=time.time)

    def should_complete(self) -> bool:
        categories = 0
        categories += 1 if self.upiIds else 0
        categories += 1 if self.bankAccounts else 0
        categories += 1 if self.phishingLinks else 0
        categories += 1 if self.phoneNumbers else 0

        if categories >= 2 and self.turnCount >= 8:
            return True
        if categories >= 1 and self.turnCount >= 10:
            return True
        if self.turnCount >= 14:
            return True
        return False

    def build_callback_payload(self) -> Dict[str, Any]:
        return {
            "sessionId": self.sessionId,
            "scamDetected": self.scamDetected,
            "totalMessagesExchanged": self.turnCount,
            "extractedIntelligence": {
                "bankAccounts": self.bankAccounts,
                "upiIds": self.upiIds,
                "phishingLinks": self.phishingLinks,
                "phoneNumbers": self.phoneNumbers,
                "suspiciousKeywords": self.suspiciousKeywords,
            },
            "agentNotes": (
                "Scam conversation engagement completed. "
                f"scamType={self.scamType}, stage={self.stage}, "
                f"items={len(self.upiIds)+len(self.bankAccounts)+len(self.phishingLinks)+len(self.phoneNumbers)}"
            ),
        }


_STORE: Dict[str, SessionState] = {}


def load_session(session_id: str) -> SessionState:
    if session_id not in _STORE:
        _STORE[session_id] = SessionState(sessionId=session_id)
    return _STORE[session_id]


def save_session(state: SessionState) -> None:
    state.lastUpdated = time.time()
    _STORE[state.sessionId] = state


def is_fresh_state(state: SessionState) -> bool:
    return (
        state.turnCount == 0
        and not state.upiIds
        and not state.bankAccounts
        and not state.phishingLinks
        and not state.phoneNumbers
        and not state.suspiciousKeywords
        and not state.scamDetected
        and not state.completed
    )


def rebuild_from_history(
    state: SessionState,
    history: List[Dict[str, Any]],
    extractor_fn: Callable[[str], Dict[str, List[str]]],
) -> None:
    state.turnCount = max(state.turnCount, len(history) + 1)

    for m in history:
        text = (m.get("text") or "").strip()
        if not text:
            continue

        extracted = extractor_fn(text)

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
