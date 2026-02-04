from typing import Tuple, Dict, Any
from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    """
    Agentic reply engine.

    IMPORTANT:
    - turnCount is incremented in app.py (one per incoming request)
    - This function must NOT increment turnCount
    - This function must NOT set state.completed=True (callback_reporter does that)
    """

    extracted = extract_all(msg_text)

    # If callback already completed, keep it short & safe
    if state.completed:
        state.stage = "EXIT"
        return "Okay, noted. Thanks.", {"stage": state.stage, "turnCount": state.turnCount}

    # React first to intel in the current scammer message
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return (
            "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return (
            "Can you resend the bank account number again? Please type it with spaces so I can copy correctly.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return (
            "I saved the number but I’m not sure the last digits are right. Can you confirm the last 2 digits?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return (
            "I tried opening it but it’s not working on my phone. Can you resend the exact link/details?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # Stage-driven conversation when no intel appears in this message
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return (
            "Why is it getting blocked? What should I do right now?",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return (
            "I’m confused and I don’t want it to get worse. Please send the exact link/UPI/account details again.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return (
            "Okay. Send the exact payment detail (UPI ID or bank account) and the verification link in one message.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    if state.stage == "VERIFY":
        if state.should_complete():
            state.stage = "EXIT"
            return (
                "Okay, I’ll try again now. Give me a minute.",
                {"stage": state.stage, "turnCount": state.turnCount},
            )

        return (
            "It’s still not going through. Please resend the link and the payment details again. "
            "If there’s an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage, "turnCount": state.turnCount},
        )

    # EXIT or unknown
    if state.should_complete():
        state.stage = "EXIT"
        return "Okay, I’m checking again. Give me a minute.", {"stage": state.stage, "turnCount": state.turnCount}

    state.stage = "EXIT"
    return "Okay, noted.", {"stage": state.stage, "turnCount": state.turnCount}
