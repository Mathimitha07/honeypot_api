# agent_engine.py
from typing import Tuple, Dict, Any

from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    """
    Agentic reply engine.
    Uses stage + turnCount to drive a believable conversation that maximizes intel extraction.

    Stages (your session_store uses):
      HOOK -> FRICTION -> EXTRACT -> VERIFY -> EXIT (we use EXIT as DONE)
    """

    extracted = extract_all(msg_text)

    # 1) Increment turn count (one per incoming message event)
    state.turnCount = (state.turnCount or 0) + 1

    # 2) If already completed, keep it safe/short
    if state.completed:
        state.stage = "EXIT"
        return "Okay, noted. Thanks.", {"stage": state.stage, "turnCount": state.turnCount}

    # 3) Context-aware friction rules (CRITICAL FIX)
    # Priority: respond to what scammer just sent.

    # UPI present -> ask to resend UPI (human error)
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return (
            "Please send the exact UPI ID again (including the @ part). I typed it wrong.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # Bank account present -> ask to resend clearly
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return (
            "Can you resend the bank account number again? Type it with spaces so I can copy correctly.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # Phone number present -> confirm last digits
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return (
            "I saved the number but I’m not sure the last digits are right. Can you confirm the last 2 digits?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # Link present -> link friction (only when link actually appears)
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return (
            "I tried opening it but it's not working on my phone. Can you resend the exact link/details?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # 4) Stage-based dialogue (fallback when no intel appears in this message)

    # HOOK: worried know-nothing user
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return (
            "Why is it getting blocked? What should I do right now?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # FRICTION: force the scammer to resend or clarify
    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return (
            "I’m confused and I don’t want it to get worse. Please send the exact link/UPI/account details again.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # EXTRACT: ask for concrete details (UPI/link/account)
    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return (
            "Okay. Send me the exact payment detail (UPI ID or bank account) and the verification link in one message.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # VERIFY: keep pushing for repeats/alternatives until should_complete()
    if state.stage == "VERIFY":
        # If we've met scoring-friendly completion rule, end engagement
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            return (
                "Okay wait. I’m checking again. Please hold for a minute.",
                {"stage": state.stage, "turnCount": state.turnCount},
            )

        # Otherwise keep extracting
        return (
            "It’s still not going through. Please resend the link and the payment details again. "
            "If there’s an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # EXIT or unknown stage fallback
    if state.should_complete():
        state.completed = True
    state.stage = "EXIT"
    return "Okay, noted.", {"stage": state.stage, "turnCount": state.turnCount}
