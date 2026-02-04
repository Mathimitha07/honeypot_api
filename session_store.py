from dataclasses import dataclass, field
from typing import List, Dict
import time

@dataclass
class SessionState:
    sessionId: str
    scamDetected: bool = False
    scamType: str = "unknown"
    stage: str = "HOOK"  # HOOK/FRICTION/EXTRACT/VERIFY/EXIT
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
        categories = 0
        categories += 1 if self.upiIds else 0
        categories += 1 if self.bankAccounts else 0
        categories += 1 if self.phishingLinks else 0
        categories += 1 if self.phoneNumbers else 0

        # Scoring-friendly completion rule
        return (self.turnCount >= 10 and categories >= 2) or (self.turnCount >= 14 and categories >= 1)

    def build_callback_payload(self) -> Dict:
        return {
            "sessionId": self.sessionId,
            "scamDetected": self.scamDetected,
            "totalMessagesExchanged": self.turnCount,
            "extractedIntelligence": {
                "bankAccounts": self.bankAccounts,
                "upiIds": self.upiIds,
                "phishingLinks": self.phishingLinks,
                "phoneNumbers": self.phoneNumbers,
                "suspiciousKeywords": self.suspiciousKeywords
            },
            "agentNotes": (
                "Scam conversation engagement completed. "
                f"scamType={self.scamType}, stage={self.stage}, "
                f"items={len(self.upiIds)+len(self.bankAccounts)+len(self.phishingLinks)+len(self.phoneNumbers)}"
            )
        }

# In-memory session store (OK for hackathon). Replace with Redis later if needed.
_STORE: Dict[str, SessionState] = {}

def load_session(session_id: str) -> SessionState:
    if session_id not in _STORE:
        _STORE[session_id] = SessionState(sessionId=session_id)
    return _STORE[session_id]

def save_session(state: SessionState) -> None:
    state.lastUpdated = time.time()
    _STORE[state.sessionId] = state
