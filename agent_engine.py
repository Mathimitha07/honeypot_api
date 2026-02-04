# agent_engine.py
from typing import Tuple, Dict, Any

from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    """
    Agentic reply engine.

    IMPORTANT:
    - turnCount should be incremented in app.py (one per incoming request).
      So do NOT increment turnCount here.
    - This function only decides: reply + stage updates.
    """

    extracted = extract_all(msg_text)

    # 1) If already completed, keep it short & safe
    if state.completed:
        state.stage = "EXIT"
        return "Okay, noted. Thanks.", {"stage": state.stage, "turnCount": state.turnCount}

    # 2) React FIRST to what the scammer just sent (high priority)
    # UPI present -> confirm/retype (human error)
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return (
            "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # Bank account present -> ask to resend clearly
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return (
            "Can you resend the bank account number again? Please type it with spaces so I can copy correctly.",
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
            "I tried opening it but it’s not working on my phone. Can you resend the exact link/details?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # 3) Stage-based dialogue (fallback when no intel appears in this message)

    # HOOK: worried / confused user
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return (
            "Why is it getting blocked? What should I do right now?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # FRICTION: force resend/clarify
    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return (
            "I’m confused and I don’t want it to get worse. Please send the exact link/UPI/account details again.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # EXTRACT: ask for concrete details
    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return (
            "Okay. Send the exact payment detail (UPI ID or bank account) and the verification link in one message.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # VERIFY: keep pushing until completion condition triggers
    if state.stage == "VERIFY":
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            # Safe ending that doesn't reveal anything and doesn't invite more scam instructions
            return (
                "Okay, I’ll try again now. Give me a minute.",
                {"stage": state.stage, "turnCount": state.turnCount},
            )

        return (
            "It’s still not going through. Please resend the link and the payment details again. "
            "If there’s an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # EXIT or unknown stage
    if state.should_complete():
        state.completed = True
    state.stage = "EXIT"
    return "Okay, noted.", {"stage": state.stage, "turnCount": state.turnCount}
