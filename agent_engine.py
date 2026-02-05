# agent_engine.py
from typing import Tuple, Dict, Any
from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    if state.completed:
        state.stage = "EXIT"
        return "Okay. I’m checking it now. Please wait.", {"stage": state.stage}

    # -------------------------
    # 1) React to intel (priority)
    # -------------------------

    # Link appeared
    if extracted.get("phishingLinks"):
        incoming = extracted.get("phishingLinks") or []
        already_known = all(l in state.phishingLinks for l in incoming)

        if already_known:
            state.linkRepeatCount += 1
        else:
            state.linkRepeatCount = 0

        state.stage = "FRICTION"

        if state.linkRepeatCount >= 1:
            return (
                "That link is loading very slowly. Can you send a shorter link or the exact steps, and the official helpline number you want me to call?",
                {"stage": state.stage},
            )

        return (
            "I tried opening it but it’s not working on my phone. Can you resend the exact link again?",
            {"stage": state.stage},
        )

    # UPI appeared
    if extracted.get("upiIds"):
        incoming = extracted.get("upiIds") or []
        already_known = all(u in state.upiIds for u in incoming)

        if already_known:
            state.upiRepeatCount += 1
        else:
            state.upiRepeatCount = 0

        state.stage = "VERIFY"

        # Ask beneficiary/alternate ONLY ONCE
        if state.upiRepeatCount >= 1:
            if not state.askedBeneficiary:
                state.askedBeneficiary = True
                return (
                    "Okay I saved it. What beneficiary name should I see while paying?",
                    {"stage": state.stage},
                )
            if not state.askedAlternate:
                state.askedAlternate = True
                return (
                    "Do you have an alternate UPI ID or a bank account + IFSC in case this fails?",
                    {"stage": state.stage},
                )

            # After asking both, pivot to “human mistake” flow (no repeating questions)
            return (
                "I’m getting a verification error on my side. Can you resend the bank account number + IFSC clearly (or the helpline number)?",
                {"stage": state.stage},
            )

        return (
            "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.",
            {"stage": state.stage},
        )

    # Bank account appeared
    if extracted.get("bankAccounts"):
        incoming = extracted.get("bankAccounts") or []
        already_known = all(b in state.bankAccounts for b in incoming)

        if already_known:
            state.bankRepeatCount += 1
        else:
            state.bankRepeatCount = 0

        state.stage = "VERIFY"

        if state.bankRepeatCount >= 1:
            # Don’t keep asking the same resend line
            return (
                "Thanks. What is the branch/region and the beneficiary name that should appear? Also share any alternate account/UPI.",
                {"stage": state.stage},
            )

        return (
            "Can you resend the bank account number again? Please type it with spaces so I can copy correctly. Also share IFSC.",
            {"stage": state.stage},
        )

    # Phone number appeared
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return (
            "I saved the number but I’m not sure the last digits are right. Can you confirm the last 2 digits?",
            {"stage": state.stage},
        )

    # -------------------------
    # 2) Stage fallback (no intel)
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
            "It’s still not going through. Please resend link and payment details again. If there’s an alternate UPI/bank account or helpline number, send that too.",
            {"stage": state.stage},
        )

    state.stage = "EXIT"
    return "Okay.", {"stage": state.stage}
