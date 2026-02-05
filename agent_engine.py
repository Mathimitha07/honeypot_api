from typing import Tuple, Dict, Any
from extractor import extract_all


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    if state.completed:
        state.stage = "EXIT"
        return "Okay, noted. Thanks.", {"stage": state.stage}

    # If intel appears, react to it
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return "Please send the exact UPI ID again (including the @ part). I think I typed it wrong.", {"stage": state.stage}

    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return "Can you resend the bank account number again? Please type it with spaces so I can copy correctly.", {"stage": state.stage}

    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return "I saved the number but I’m not sure the last digits are right. Can you confirm the last 2 digits?", {"stage": state.stage}

    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return "I tried opening it but it’s not working on my phone. Can you resend the exact link again?", {"stage": state.stage}

    # Stage based fallback
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return "Why is it getting blocked? What should I do right now?", {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return "I’m confused. Please send the exact verification link and payment details again.", {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return "Okay. Send the verification link plus payment detail (UPI ID or bank account) in one message.", {"stage": state.stage}

    if state.stage == "VERIFY":
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            return "Okay, I’ll try again now. Give me a minute.", {"stage": state.stage}

        return "It’s still not going through. Please resend link + payment details again. If alternate UPI/account exists, send that too.", {"stage": state.stage}

    state.stage = "EXIT"
    return "Okay.", {"stage": state.stage}
