# agent_engine.py
from typing import Tuple, Dict, Any
from extractor import extract_all


def _pick(state, intent: str, options):
    # anti-loop: if same intent repeats, rotate options harder
    if state.lastIntent == intent:
        state.repeatIntentCount += 1
    else:
        state.lastIntent = intent
        state.repeatIntentCount = 0

    if not options:
        return ""

    idx = (state.personaSeed + state.turnCount + state.repeatIntentCount) % len(options)
    return options[idx]


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # If already completed, don't loop
    if state.completed:
        state.stage = "EXIT"
        return _pick(state, "EXIT", [
            "Okay, I’m checking now. Please wait.",
            "One minute, my app is loading.",
            "Hold on, network is weak here."
        ]), {"stage": state.stage}

    # Natural exit once completion rule triggers
    if state.should_complete():
        state.completed = True
        state.stage = "EXIT"
        return _pick(state, "EXIT_FINAL", [
            "OTP still hasn’t come. I’ll call the bank helpline and update.",
            "My app crashed. I’ll retry in a bit.",
            "Network is bad here, I’m stepping outside and trying again."
        ]), {"stage": state.stage}

    # React to new intel without repeating the same line
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return _pick(state, "ASK_LINK", [
            "The link is loading very slowly. Can you send a shorter link or exact steps?",
            "It says ‘invalid page’ on my phone. Can you resend the link cleanly?",
            "It’s asking weird permissions. Is that normal? What should I click first?",
            "Can you share the support number too in case the link fails?"
        ]), {"stage": state.stage}

    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return _pick(state, "ASK_UPI_CONFIRM", [
            "My UPI app shows ‘invalid handle’. Is it @ybl / @okhdfcbank / @upi type?",
            "What beneficiary name should appear for this UPI?",
            "PhonePe shows ‘name mismatch’. What exact name should I see?",
            "If UPI fails, can I do bank transfer? Share account number + IFSC."
        ]), {"stage": state.stage}

    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return _pick(state, "ASK_BANK_PLUS", [
            "Okay, noted. What IFSC should I use and what beneficiary name will show?",
            "My app needs IFSC + branch. Send IFSC and branch/region.",
            "If this is official, tell me the beneficiary name exactly as it should appear.",
            "Do you have an alternate account or UPI as backup?"
        ]), {"stage": state.stage}

    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return _pick(state, "ASK_PHONE_CONFIRM", [
            "Is this your official support number? Any alternate helpline?",
            "I’ll call now. What should I say to verify quickly?",
            "OTP isn’t coming. Should I call this number or another one?"
        ]), {"stage": state.stage}

    # Stage flow
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return _pick(state, "HOOK", [
            "Why is it getting blocked? What should I do right now?",
            "Is this really SBI? What’s the next step?",
            "I’m scared. What do I do first?"
        ]), {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return _pick(state, "FRICTION", [
            "I’m outside and network is weak. Send link + payment details + helpline number.",
            "Before I do anything, tell me beneficiary name and IFSC so I don’t send wrong.",
            "OTP isn’t coming. Which support number should I call?"
        ]), {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return _pick(state, "EXTRACT", [
            "Send link + payment details (UPI or account + IFSC) in one message.",
            "Send the helpline number + link. If UPI fails, share bank account + IFSC.",
            "What beneficiary name should appear and what’s the IFSC? Send everything together."
        ]), {"stage": state.stage}

    # VERIFY probing (missing fields)
    state.stage = "VERIFY"
    probes = []
    if not state.beneficiaryNames:
        probes.append("My app shows ‘name mismatch’. What beneficiary name should I see exactly?")
    if not state.ifscCodes:
        probes.append("If UPI fails I’ll do bank transfer. Share IFSC + branch/region.")
    if not state.phoneNumbers:
        probes.append("OTP is not coming. Which number should I call? Send helpline number.")

    probes += [
        "The link is asking security questions. Is that normal? Tell me exact steps.",
        "Can you send a screenshot of the verification page so I can match it?",
        "I’m using my mother’s phone, OTP comes late. What’s the OTP time limit?"
    ]

    return _pick(state, "VERIFY_PROBE", probes), {"stage": state.stage}
