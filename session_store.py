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

    upiIds: List[str] = field(default_factory=list)
    bankAccounts: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)

    lastUpdated: float = field(default_factory=time.time)

    def should_complete(self) -> bool:
        """
        Callback-safe completion rules.
        Goal: avoid "no callback" scoring failures, but also avoid ending too early.
        """
        categories = 0
        categories += 1 if self.upiIds else 0
        categories += 1 if self.bankAccounts else 0
        categories += 1 if self.phishingLinks else 0
        categories += 1 if self.phoneNumbers else 0

        # Strong signal: 2 categories + enough engagement
        if categories >= 2 and self.turnCount >= 8:
            return True

        # Medium signal: 1 category + good engagement
        if categories >= 1 and self.turnCount >= 10:
            return True

        # Hard stop: always finalize at some point
        if self.turnCount >= 14:
            return True

        return False

    def build_callback_payload(self) -> Dict[str, Any]:
        items = len(self.upiIds) + len(self.bankAccounts) + len(self.phishingLinks) + len(self.phoneNumbers)
        categories = sum([
            1 if self.upiIds else 0,
            1 if self.bankAccounts else 0,
            1 if self.phishingLinks else 0,
            1 if self.phoneNumbers else 0,
        ])

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
                f"categories={categories}, items={items}, keywords={len(self.suspiciousKeywords)}"
            ),
        }


# -------------------------
# In-memory session store (OK for hackathon). Replace with Redis later if needed.
# -------------------------
_STORE: Dict[str, SessionState] = {}


def load_session(session_id: str) -> SessionState:
    if session_id not in _STORE:
        _STORE[session_id] = SessionState(sessionId=session_id)
    return _STORE[session_id]


def save_session(state: SessionState) -> None:
    state.lastUpdated = time.time()
    _STORE[state.sessionId] = state


def is_fresh_state(state: SessionState) -> bool:
    """True if this session was just created and has no meaningful state yet."""
    return (
        state.turnCount == 0
        and not state.upiIds
        and not state.bankAccounts
        and not state.phishingLinks
        and not state.phoneNumbers
        and not state.suspiciousKeywords
        and not state.scamDetected
    )


def rebuild_from_history(
    state: SessionState,
    history: List[Dict[str, Any]],
    extractor_fn: Callable[[str], Dict[str, List[str]]],
) -> None:
    """
    Rebuilds intel from conversationHistory if server restarted and memory is lost.
    extractor_fn should be extract_all(text) from extractor.py

    IMPORTANT:
    - app.py should increment turnCount for the current incoming message,
      so here we set turnCount to len(history) (not +1).
    """

    # Past turns = number of messages in history
    state.turnCount = max(state.turnCount, len(history))

    for m in history:
        text = (m.get("text") or "").strip()
        if not text:
            continue

        extracted = extractor_fn(text)

        # Merge unique extracted values
        for k in ["upiIds", "bankAccounts", "phishingLinks", "phoneNumbers"]:
            vals = extracted.get(k, []) or []
            if not vals:
                continue
            current = getattr(state, k, [])
            for v in vals:
                if v not in current:
                    current.append(v)
            setattr(state, k, current)

        # Merge suspicious keywords
        for w in extracted.get("suspiciousKeywords", []) or []:
            if w not in state.suspiciousKeywords:
                state.suspiciousKeywords.append(w)
