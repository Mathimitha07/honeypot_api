# agent_engine.py
from typing import Tuple, Dict, Any, List
from extractor import extract_all


def _set_intent(state, intent: str) -> None:
    """Tracks repetition to avoid loopy behavior."""
    if state.lastIntent == intent:
        state.repeatIntentCount += 1
    else:
        state.lastIntent = intent
        state.repeatIntentCount = 0


def _pick(state, options: List[str]) -> str:
    """
    Deterministic-ish variety without randomness:
    rotates based on personaSeed + turnCount + repeatIntentCount.
    """
    if not options:
        return ""
    idx = (state.personaSeed + state.turnCount + state.repeatIntentCount) % len(options)
    return options[idx]


def _pick_excuse(state, options: List[str]) -> str:
    """
    Choose an excuse we haven't used yet (prevents repeating same excuse).
    Falls back to rotation if all used.
    """
    unused = [x for x in options if x not in state.usedExcuses]
    if unused:
        choice = _pick(state, unused)
        state.usedExcuses.append(choice)
        return choice
    # all used -> rotate anyway
    return _pick(state, options)


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # If already completed (callback succeeded), do not engage further
    if state.completed:
        state.stage = "EXIT"
        _set_intent(state, "EXIT_DONE")
        exit_done = [
            "Okay, noted. Thanks.",
            "Alright. I’ll handle it.",
            "Okay. I’m checking.",
        ]
        return _pick(state, exit_done), {"stage": state.stage}

    # -------------------------
    # 0) If ready to finalize, exit naturally BUT do NOT set completed=True here.
    # -------------------------
    if state.should_complete():
        state.stage = "EXIT"
        _set_intent(state, "EXIT_PENDING")
        exit_lines = [
            "OTP still hasn’t come. I’m going to call the bank helpline first.",
            "My app crashed just now. I’ll retry in a bit and update you.",
            "Network is weak here. I’ll try again after I move outside and call support.",
            "I’m going to the branch counter now. I’ll message after they confirm.",
            "I can’t see the OTP SMS. I’ll restart the phone and try once more.",
        ]
        return _pick_excuse(state, exit_lines), {"stage": state.stage}

    # -------------------------
    # 1) React to NEW intel in THIS message (priority)
    # -------------------------

    # Link present -> progressive friction (avoid same "invalid" line)
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        _set_intent(state, "HANDLE_LINK")

        link_tactics = [
            "The link is loading very slowly. Can you send a shorter link or the exact steps?",
            "It says ‘invalid page’ on my phone. Can you resend the link without any extra dots or symbols?",
            "It’s asking for strange permissions. Is that normal? What exactly should I click first?",
            "It opens and closes immediately. Can you send a bit.ly/tinyurl link and the helpline number?",
            "It’s stuck on a blank page. Can you send a screenshot of what the page should look like?",
        ]
        return _pick(state, link_tactics), {"stage": state.stage}

    # UPI present -> vary verification prompts + ask beneficiary/alternate methods
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        _set_intent(state, "HANDLE_UPI")

        upi_tactics = [
            "My UPI app shows ‘invalid handle’. Is it @ybl / @okhdfcbank / @upi type? Please confirm the exact handle.",
            "Before I pay, what beneficiary name should show on the UPI screen?",
            "Google Pay shows ‘name mismatch’. What exact name should appear for this UPI?",
            "If UPI fails, can I do bank transfer? Share account number + IFSC.",
            "Should I use PhonePe or GPay for this UPI? One of them is not accepting it.",
        ]
        return _pick(state, upi_tactics), {"stage": state.stage}

    # Bank account present -> ask IFSC/beneficiary/branch; avoid “resend again” loop
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        _set_intent(state, "HANDLE_BANK")

        bank_tactics = [
            "Okay I noted the account. What IFSC code should I use, and what beneficiary name will show?",
            "My banking app needs IFSC + branch. Please send IFSC and branch/region.",
            "If this is official, tell me the beneficiary name exactly as it should appear.",
            "Do you have an alternate account or UPI as backup? Send both.",
            "Is it savings or current account? Also share IFSC so I don’t make a mistake.",
        ]
        return _pick(state, bank_tactics), {"stage": state.stage}

    # Phone present -> confirm + ask alternate
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        _set_intent(state, "HANDLE_PHONE")

        phone_tactics = [
            "Which number should I call back? This message came from an unknown sender.",
            "Is this your official support number? Share the alternate helpline too.",
            "I’ll call now. What exactly should I say to verify?",
            "If this number is busy, what’s the second number I should try?",
        ]
        return _pick(state, phone_tactics), {"stage": state.stage}

    # -------------------------
    # 2) Stage-based structured extraction sequence
    # -------------------------

    if state.stage == "HOOK":
        state.stage = "FRICTION"
        _set_intent(state, "HOOK")

        hook_lines = [
            "Why is it getting blocked? What should I do right now?",
            "I don’t understand… what happened to my account?",
            "Is this really SBI? I’m scared. What’s the next step?",
        ]
        return _pick(state, hook_lines), {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        _set_intent(state, "FRICTION")

        friction_lines = [
            "I’m outside and network is weak. Send the exact link and the helpline number you want me to call.",
            "Before I do anything, tell me the beneficiary name and IFSC. I don’t want to send to wrong person.",
            "If OTP doesn’t come, which support number should I call? Send the number.",
            "Can you send the payment details again (UPI / account + IFSC) in one message so I don’t make mistakes?",
        ]
        return _pick_excuse(state, friction_lines), {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        _set_intent(state, "EXTRACT")

        extract_lines = [
            "Okay. Send link + payment details (UPI or account + IFSC) together.",
            "Send the official helpline number + link. If UPI fails, share bank account + IFSC.",
            "What beneficiary name should appear, and what’s the IFSC? Send everything in one message.",
        ]
        return _pick(state, extract_lines), {"stage": state.stage}

    if state.stage == "VERIFY":
        _set_intent(state, "VERIFY")

        missing_ifsc = not state.ifscCodes
        missing_beneficiary = not state.beneficiaryNames
        missing_phone = not state.phoneNumbers

        probe_pool: List[str] = []

        if missing_beneficiary:
            probe_pool.append("My app shows ‘name mismatch’. What beneficiary name should I see exactly?")
        if missing_ifsc:
            probe_pool.append("If UPI fails, I’ll do bank transfer. Share IFSC + branch/region.")
        if missing_phone:
            probe_pool.append("OTP is not coming. Which number should I call? Send the helpline number.")

        probe_pool += [
            "The link is asking security questions. Is that normal? Send the exact steps.",
            "Can you send a screenshot of the payment/verification page so I can match it?",
            "I’m using my mother’s phone, OTP comes late sometimes. What’s the OTP time limit?",
            "Should I select ‘account blocked’ or ‘KYC pending’ in the menu? Which option is correct?",
        ]

        return _pick(state, probe_pool), {"stage": state.stage}

    # Fallback (should rarely happen)
    state.stage = "VERIFY"
    _set_intent(state, "FALLBACK")
    fallback = [
        "Can you resend the details clearly once? (link + payment info)",
        "Send the steps again, and also the support number.",
        "Please send UPI/account + IFSC in one message.",
    ]
    return _pick(state, fallback), {"stage": state.stage}
