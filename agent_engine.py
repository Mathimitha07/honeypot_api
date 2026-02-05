# agent_engine.py
from typing import Tuple, Dict, Any
from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    """
    Agentic reply engine.

    IMPORTANT:
    - turnCount is incremented in app.py (one per incoming request).
    - This function only decides: reply + stage updates.
    """

    extracted = extract_all(msg_text)

    # If already completed, keep it short & safe
    if state.completed:
        state.stage = "EXIT"
        return "Okay. I’m checking it now. Please wait.", {"stage": state.stage}

    # -------------------------
    # React FIRST to intel in this message (priority)
    # -------------------------

    # UPI present -> ask once, then pivot to new intel instead of repeating
    if extracted.get("upiIds"):
        incoming_upis = extracted.get("upiIds") or []
        already_known = all(u in state.upiIds for u in incoming_upis)

        if already_known:
            state.upiRepeatCount += 1
        else:
            state.upiRepeatCount = 0

        state.stage = "VERIFY"

        # If scammer keeps repeating same UPI, pivot hard
        if state.upiRepeatCount >= 1:
            return (
                "Okay I saved that. What beneficiary name should I see while paying, and do you have an alternate UPI or bank account + IFSC?",
                {"stage": state.stage},
            )

        return (
            "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.",
            {"stage": state.stage},
        )

    # Bank account present -> ask to resend clearly (human error)
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return (
            "Can you resend the bank account number again? Please type it with spaces so I can copy correctly. Also share IFSC.",
            {"stage": state.stage},
        )

    # Phone number present -> confirm last digits
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return (
            "I saved the number but I’m not sure the last digits are right. Can you confirm the last 2 digits and the name of the person I should ask for?",
            {"stage": state.stage},
        )

    # Link present -> ask once, then pivot to steps/alternate link
    if extracted.get("phishingLinks"):
        incoming_links = extracted.get("phishingLinks") or []
        already_known = all(l in state.phishingLinks for l in incoming_links)

        if already_known:
            state.linkRepeatCount += 1
        else:
            state.linkRepeatCount = 0

        state.stage = "FRICTION"

        if state.linkRepeatCount >= 1:
            return (
                "The link is opening slowly. Can you send a shorter link or the exact steps, and the official helpline number you want me to call?",
                {"stage": state.stage},
            )

        return (
            "I tried opening it but it’s not working on my phone. Can you resend the exact link again?",
            {"stage": state.stage},
        )

    # -------------------------
    # Stage-based fallback when this message has no new intel
    # -------------------------

    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return "Why is it getting blocked? What should I do right now?", {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return (
            "I’m confused. Please send the exact verification link and payment details again (UPI or bank + IFSC).",
            {"stage": state.stage},
        )

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return (
            "Okay. Send the verification link plus payment detail (UPI ID or bank account + IFSC) in one message.",
            {"stage": state.stage},
        )

    if state.stage == "VERIFY":
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            return "Okay, I’m trying again now. Give me a minute.", {"stage": state.stage}

        return (
            "It’s still not going through. Please resend the link and payment details again. If there’s an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage},
        )

    # EXIT / unknown
    state.stage = "EXIT"
    return "Okay.", {"stage": state.stage}
