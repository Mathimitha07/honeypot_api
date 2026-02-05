# session_store.py
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Any, Set
import time


@dataclass
class SessionState:
    sessionId: str

    scamDetected: bool = False
    scamType: str = "unknown"
    stage: str = "HOOK"  # HOOK / FRICTION / EXTRACT / VERIFY / EXIT

    # counts incoming unique events (after dedupe)
    turnCount: int = 0

    completed: bool = False
    callbackFailures: int = 0

    # extracted intel
    upiIds: List[str] = field(default_factory=list)
    bankAccounts: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    ifscCodes: List[str] = field(default_factory=list)
    beneficiaryNames: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)

    # anti-loop + realism controls
    personaSeed: int = 0
    lastIntent: str = ""
    repeatIntentCount: int = 0
    usedExcuses: List[str] = field(default_factory=list)

    # dedupe protection
    seenFingerprints: Set[str] = field(default_factory=set)

    # useful for callback "both sides" counting
    lastHistoryLen: int = 0

    lastUpdated: float = field(default_factory=time.time)

    def should_complete(self) -> bool:
        """
        Aim for 12–18 turns unless we already got rich intel.
        Hard stop ensures callback will happen.
        """
        categories = 0
        categories += 1 if self.upiIds else 0
        categories += 1 if self.bankAccounts else 0
        categories += 1 if self.phishingLinks else 0
        categories += 1 if self.phoneNumbers else 0
        categories += 1 if self.ifscCodes else 0
        categories += 1 if self.beneficiaryNames else 0

        # If rich intel (3+ categories), allow earlier finish but not too early
        if categories >= 3 and self.turnCount >= 10:
            return True

        # Normal finish window
        if categories >= 2 and self.turnCount >= 12:
            return True

        # If only 1 category, keep engaging longer
        if categories >= 1 and self.turnCount >= 16:
            return True

        # Hard stop to always trigger callback
        if self.turnCount >= 18:
            return True

        return False

    def total_messages_exchanged(self) -> int:
        """
        GUVI-friendly: count BOTH sides based on history.
        total = previous history + current incoming + our outgoing
        """
        return int(self.lastHistoryLen) + 2

    def build_callback_payload(self) -> Dict[str, Any]:
        """
        STRICT schema: only the keys GUVI expects.
        Do NOT include extra keys in extractedIntelligence.
        """
        return {
            "sessionId": self.sessionId,
            "scamDetected": self.scamDetected,
            "totalMessagesExchanged": self.total_messages_exchanged(),
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


# -------------------------
# In-memory store
# -------------------------
_STORE: Dict[str, SessionState] = {}


def load_session(session_id: str) -> SessionState:
    if session_id not in _STORE:
        seed = abs(hash(session_id)) % 3
        _STORE[session_id] = SessionState(sessionId=session_id, personaSeed=seed)
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
        and not state.ifscCodes
        and not state.beneficiaryNames
        and not state.suspiciousKeywords
        and not state.scamDetected
    )


def rebuild_from_history(
    state: SessionState,
    history: List[Dict[str, Any]],
    extractor_fn: Callable[[str], Dict[str, List[str]]],
) -> None:
    """
    Rebuild state if Render slept/restarted and memory got wiped.
    Only merges extracted items from history text.
    """
    if not isinstance(history, list):
        return

    # state.turnCount will be incremented in app.py after dedupe,
    # but we set a baseline so it doesn't start from zero after restart.
    state.turnCount = max(state.turnCount, len(history) // 2)

    for m in history:
        if not isinstance(m, dict):
            continue
        text = (m.get("text") or "").strip()
        if not text:
            continue

        extracted = extractor_fn(text)

        for k in [
            "upiIds",
            "bankAccounts",
            "phishingLinks",
            "phoneNumbers",
            "ifscCodes",
            "beneficiaryNames",
        ]:
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
