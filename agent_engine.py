# agent_engine.py
from typing import Tuple, Dict, Any, List

from extractor import extract_all


def _rotate(state, intent: str, options: List[str]) -> str:
    """
    Anti-loop:
    - Track intent. If same intent repeats too much, force next option.
    - Use personaSeed + turnCount to rotate naturally.
    """
    if state.lastIntent == intent:
        state.repeatIntentCount += 1
    else:
        state.lastIntent = intent
        state.repeatIntentCount = 0

    # If we're repeating, push to a different variation
    shift = min(state.repeatIntentCount, len(options) - 1)
    idx = (state.personaSeed + state.turnCount + shift) % len(options)
    return options[idx] if options else "Okay."


def _one_time_excuse(state, options: List[str]) -> str:
    """
    Avoid repeating same excuse lines across turns.
    """
    for opt in options:
        if opt not in state.usedExcuses:
            state.usedExcuses.append(opt)
            return opt
    # if all used, rotate deterministically
    idx = (state.personaSeed + state.turnCount) % len(options)
    return options[idx]


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # If already completed: stall safely (no loops)
    if state.completed:
        state.stage = "EXIT"
        return _rotate(
            state,
            "EXIT_STALL",
            [
                "Okay, I’m checking. Please wait.",
                "One minute, I’m trying again.",
                "Hold on, the app is loading.",
            ],
        ), {"stage": state.stage}

    # If we are ready to complete, exit naturally
    if state.should_complete():
        state.completed = True
        state.stage = "EXIT"
        return _one_time_excuse(
            state,
            [
                "OTP still hasn’t come. I’m going to call the bank helpline first.",
                "My app crashed. I’ll retry in a bit and confirm.",
                "Network is weak here. I’ll try again after I move outside.",
                "I’m going to the branch counter now, I’ll update you after they check.",
            ],
        ), {"stage": state.stage}

    # -------------------------
    # React to new intel in THIS message (priority)
    # -------------------------

    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        return _rotate(
            state,
            "ASK_LINK_VARIATION",
            [
                "The link is loading very slowly. Can you send a shorter link or the exact steps?",
                "It says ‘invalid page’ on my phone. Can you resend the link without extra symbols?",
                "It’s asking weird permissions. Is that normal? Send the exact steps.",
                "It opens and closes. Can you send an alternate link and the helpline number?",
            ],
        ), {"stage": state.stage}

    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        return _rotate(
            state,
            "ASK_UPI_VARIATION",
            [
                "My UPI app shows ‘invalid handle’. Is it @ybl / @okhdfcbank / @upi type? Please confirm.",
                "Before I pay, what beneficiary name should show on the UPI screen?",
                "Google Pay shows ‘name mismatch’. What exact name should appear for this UPI?",
                "If UPI fails, can I do bank transfer? Share account number + IFSC.",
            ],
        ), {"stage": state.stage}

    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        return _rotate(
            state,
            "ASK_BANK_IFSC_BENEF",
            [
                "Okay I noted the account. What IFSC code should I use, and what beneficiary name will show?",
                "My bank app needs IFSC + branch. Please send IFSC and branch/region.",
                "If this is official, tell me the beneficiary name exactly as it should appear.",
                "If bank transfer fails, do you have an alternate account or UPI? Share both.",
            ],
        ), {"stage": state.stage}

    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        return _rotate(
            state,
            "ASK_PHONE_CONFIRM",
            [
                "Which number should I call back? This message came from an unknown sender.",
                "Is this your official support number? Share the alternate helpline too.",
                "I’ll call this number now. What should I say exactly to verify?",
            ],
        ), {"stage": state.stage}

    # -------------------------
    # Stage-based plan (structured extraction sequence)
    # -------------------------
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        return _rotate(
            state,
            "HOOK_LINES",
            [
                "Why is it getting blocked? What should I do right now?",
                "I don’t understand… what happened to my account?",
                "Is this really SBI? I’m scared. What’s the next step?",
            ],
        ), {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        return _rotate(
            state,
            "FRICTION_PLAN",
            [
                "I’m outside and network is weak. Send the exact link and the helpline number.",
                "Before I do anything, tell me the beneficiary name and IFSC. I don’t want to send to wrong person.",
                "OTP isn’t coming sometimes. Which support number should I call? Send the number.",
                "Can you send the payment details again (UPI / account + IFSC) in one message?",
            ],
        ), {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        return _rotate(
            state,
            "EXTRACT_DETAILS",
            [
                "Okay. Send link + payment details (UPI or account + IFSC) together.",
                "Send the helpline number + link. If UPI fails, share bank account + IFSC.",
                "What beneficiary name should appear, and what’s the IFSC? Send everything in one message.",
            ],
        ), {"stage": state.stage}

    # VERIFY: probe missing high-value fields progressively
    if state.stage == "VERIFY":
        missing_benef = not state.beneficiaryNames
        missing_ifsc = not state.ifscCodes
        missing_phone = not state.phoneNumbers
        missing_link = not state.phishingLinks

        probes: List[str] = []

        if missing_link:
            probes.append("I can’t find the official verification page. Can you send the exact link again?")
        if missing_benef:
            probes.append("My app shows ‘name mismatch’. What beneficiary name should I see exactly?")
        if missing_ifsc:
            probes.append("If UPI fails, I’ll do bank transfer. Share IFSC + branch/region.")
        if missing_phone:
            probes.append("OTP is not coming. Which number should I call? Send the helpline number.")

        probes += [
            "The link is asking security questions. Is that normal? Send the exact steps.",
            "Can you send a screenshot of the verification page so I can match it?",
            "I’m using my mother’s phone, OTP comes late sometimes. What’s the time limit?",
        ]

        return _rotate(state, "VERIFY_PROBES", probes), {"stage": state.stage}

    # Fallback
    state.stage = "VERIFY"
    return _rotate(
        state,
        "FALLBACK",
        [
            "Can you resend the details clearly once? (link + payment info)",
            "Please send the link and payment details again in one message so I don’t make mistakes.",
        ],
    ), {"stage": state.stage}
