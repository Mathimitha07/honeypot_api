# agent_engine.py
from typing import Tuple, Dict, Any

from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    """
    Agentic reply engine.

    Rules:
    - turnCount MUST be incremented in app.py (one per request).
      Do NOT increment turnCount here.
    - This function decides reply + stage transitions only.
    """

    extracted = extract_all(msg_text)

    # 1) If already completed, keep it short & safe
    if state.completed:
        state.stage = "EXIT"
        return "Okay, noted. Thanks.", {"stage": state.stage}

    # 2) React FIRST to what the scammer just sent (priority extraction)

    # UPI present -> ask to resend UPI (human error)
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return (
            "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.",
            {"stage": state.stage},
        )

    # Bank account present -> ask to resend clearly
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return (
            "Can you resend the bank account number again? Please type it with spaces so I can copy correctly.",
            {"stage": state.stage},
        )

    # Phone number present -> confirm last digits
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return (
            "I saved the number but I'm not sure the last digits are right. Can you confirm the last 2 digits?",
            {"stage": state.stage},
        )

    # Link present -> link friction (only when link appears)
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return (
            "I tried opening it but it's not working on my phone. Can you resend the exact link/details?",
            {"stage": state.stage},
        )

    # 3) Stage-based dialogue (fallback when no new intel appears)

    # HOOK: worried / confused user
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return (
            "Why is it getting blocked? What should I do right now?",
            {"stage": state.stage},
        )

    # FRICTION: force resend/clarify
    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return (
            "I'm confused and I don't want it to get worse. Please send the exact link/UPI/account details again.",
            {"stage": state.stage},
        )

    # EXTRACT: ask for concrete details
    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return (
            "Okay. Send the exact payment detail (UPI ID or bank account) and the verification link in one message.",
            {"stage": state.stage},
        )

    # VERIFY: keep pushing until completion condition triggers
    if state.stage == "VERIFY":
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            # Safe ending: does not reveal detection and does not invite more instructions
            return (
                "Okay, I'll try again now. Give me a minute.",
                {"stage": state.stage},
            )

        return (
            "It's still not going through. Please resend the link and the payment details again. "
            "If there's an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage},
        )

    # EXIT or unknown stage fallback
    if state.should_complete():
        state.completed = True
    state.stage = "EXIT"
    return "Okay, noted.", {"stage": state.stage}
