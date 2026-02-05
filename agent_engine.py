# agent_engine.py
from typing import Tuple, Dict, Any
from extractor import extract_all


def _persona_line(state) -> str:
    # small human excuse once in a while (not every turn)
    if state.turnCount in (2, 5, 8):
        if state.personaSeed == 0:
            return "I’m outside and my network is weak. "
        if state.personaSeed == 1:
            return "I’m using my mother’s phone and things are slow. "
        return "My UPI app is lagging right now. "
    return ""


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # If already completed, keep safe and stop engagement
    if state.completed:
        state.stage = "EXIT"
        return "Okay. I’m checking it now. Please wait.", {"stage": state.stage}

    # If scammer sends fresh intel, react and also ask for MORE fields (bank+IFSC / phone / beneficiary)
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        state.frictionRepeatCount += 1
        prefix = _persona_line(state)
        if state.frictionRepeatCount == 1:
            return prefix + "That link is loading very slowly. Can you send a shorter link or the exact steps, and the official helpline number you want me to call?", {"stage": state.stage}
        return prefix + "It says invalid on my phone. Please resend the exact link without any extra symbols, and share the support number to call back.", {"stage": state.stage}

    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        state.verifyRepeatCount += 1
        prefix = _persona_line(state)

        # Rotate tactics instead of repeating the same line
        if state.verifyRepeatCount == 1:
            return prefix + "Please confirm the exact UPI handle (like @ybl / @okhdfcbank / @paytm). My app is showing a mismatch.", {"stage": state.stage}
        if state.verifyRepeatCount == 2:
            return prefix + "My UPI app shows ‘Name mismatch’. What beneficiary name should I see while paying?", {"stage": state.stage}
        return prefix + "If UPI fails, can I do bank transfer instead? Share account number + IFSC and the beneficiary name.", {"stage": state.stage}

    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        state.verifyRepeatCount += 1
        prefix = _persona_line(state)

        if state.verifyRepeatCount == 1:
            return prefix + "Can you resend the bank account number with spaces so I can copy correctly? Also share IFSC.", {"stage": state.stage}
        if state.verifyRepeatCount == 2:
            return prefix + "Which branch/region is this and what beneficiary name should appear? Also send an alternate account/UPI if you have.", {"stage": state.stage}
        return prefix + "If the bank transfer fails, what number should I call back? This message came from an unknown sender.", {"stage": state.stage}

    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        prefix = _persona_line(state)
        return prefix + "Okay saved. Before I call, confirm the department name and the last 2 digits so I don’t call the wrong number.", {"stage": state.stage}

    # No new intel in this message: stage-based conversation flow
    prefix = _persona_line(state)

    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return prefix + "Why is it getting blocked? What should I do right now?", {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return prefix + "I’m confused. Please send the exact verification link and payment details again (UPI or bank + IFSC).", {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return prefix + "Okay. Send the link, then the payment details (UPI or bank + IFSC) and the beneficiary name in one message.", {"stage": state.stage}

    if state.stage == "VERIFY":
        # if completion achieved, end naturally (don’t invite more)
        if state.should_complete():
            state.completed = True
            state.stage = "EXIT"
            return "Okay, I’m trying again now. Give me a minute.", {"stage": state.stage}

        # rotate prompts in VERIFY to avoid repetition
        state.verifyRepeatCount += 1
        if state.verifyRepeatCount % 3 == 1:
            return prefix + "It’s still not going through. Please resend the link and payment details again. If there’s an alternate UPI/bank account + IFSC, send that too.", {"stage": state.stage}
        if state.verifyRepeatCount % 3 == 2:
            return prefix + "My app shows beneficiary mismatch. What exact beneficiary name should I see, and which branch/region is this?", {"stage": state.stage}
        return prefix + "Which number should I call back? This message came from an unknown sender. Share the support number and reference ID.", {"stage": state.stage}

    # fallback
    if state.should_complete():
        state.completed = True
    state.stage = "EXIT"
    return "Okay.", {"stage": state.stage}
