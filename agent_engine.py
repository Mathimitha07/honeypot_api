# agent_engine.py
from typing import Tuple, Dict, Any, List
from extractor import extract_all


def _set_intent(state, intent: str) -> None:
    """Track intent repetition to avoid loops."""
    if getattr(state, "lastIntent", "") == intent:
        state.repeatIntentCount = getattr(state, "repeatIntentCount", 0) + 1
    else:
        state.lastIntent = intent
        state.repeatIntentCount = 0


def _pick(state, options: List[str]) -> str:
    """
    Deterministic-ish variety based on session seed + turn count + intent repeat count.
    Avoids returning the same line over and over.
    """
    if not options:
        return "Okay."
    idx = (state.personaSeed + state.turnCount + state.repeatIntentCount) % len(options)
    return options[idx]


def _pick_new_excuse(state, options: List[str]) -> str:
    """
    Prefer lines not used before; if all used, fallback to deterministic pick.
    """
    used = set(getattr(state, "usedExcuses", []) or [])
    fresh = [x for x in options if x not in used]
    choice = _pick(state, fresh if fresh else options)
    if choice not in used:
        state.usedExcuses.append(choice)
    return choice


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # -------------------------
    # If already completed: keep it short, don't loop
    # -------------------------
    if state.completed:
        state.stage = "EXIT"
        _set_intent(state, "EXIT_STALL")
        stall_lines = [
            "Okay, I’m checking. Please wait.",
            "One minute, the app is loading.",
            "Hold on, OTP isn’t coming yet. I’ll try once more.",
        ]
        return _pick_new_excuse(state, stall_lines), {"stage": state.stage}

    # -------------------------
    # If we should complete: exit naturally (varied excuses)
    # -------------------------
    if state.should_complete():
        state.completed = True
        state.stage = "EXIT"
        _set_intent(state, "EXIT_COMPLETE")
        exit_lines = [
            "OTP still hasn’t come. I’m going to call the bank helpline first.",
            "My app crashed. I’ll retry after restarting and update you.",
            "Network is weak here. I’ll try again after I move outside.",
            "I’m going to the branch counter now. I’ll message after they check.",
        ]
        return _pick_new_excuse(state, exit_lines), {"stage": state.stage}

    # -------------------------
    # React to NEW intel in THIS message (priority)
    # -------------------------

    # 1) Link handling: ASK MAX 2 TIMES, then PIVOT
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        _set_intent(state, "LINK_FRICTION")
        state.linkAskCount = getattr(state, "linkAskCount", 0) + 1

        if state.linkAskCount <= 2:
            link_asks = [
                "It opens but shows blank. Paste the full verification link exactly (no short link).",
                "It says ‘invalid page’ on my phone. Send the full URL again without extra dots/symbols.",
            ]
            return _pick_new_excuse(state, link_asks), {"stage": state.stage}

        # pivot after 2
        pivot_after_link = [
            "Link still isn’t opening. Give me your UPI ID and the exact beneficiary name that should appear in GPay.",
            "This link method isn’t working. Share bank account number + IFSC + branch city so I can do bank transfer verification.",
            "OTP isn’t coming. Which support number should I call? Send the helpline number.",
        ]
        return _pick_new_excuse(state, pivot_after_link), {"stage": state.stage}

    # 2) UPI handling: do not ask “send UPI again” repeatedly
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        _set_intent(state, "UPI_PROBE")
        state.upiAskCount = getattr(state, "upiAskCount", 0) + 1

        upi_lines = [
            "My UPI app shows ‘invalid handle’. Is it @ybl / @okhdfcbank / @upi type? Please confirm.",
            "Before I pay, what exact beneficiary name should appear for this UPI?",
            "Google Pay is showing ‘name mismatch’. What exact name should appear for this UPI?",
            "If UPI fails, can I do bank transfer? Share account number + IFSC + branch.",
        ]
        return _pick_new_excuse(state, upi_lines), {"stage": state.stage}

    # 3) Bank handling: ask IFSC + beneficiary instead of “resend number”
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        _set_intent(state, "BANK_PROBE")
        state.bankAskCount = getattr(state, "bankAskCount", 0) + 1

        bank_lines = [
            "Okay I noted the account. What IFSC code should I use, and what beneficiary name will show?",
            "My bank app needs IFSC + branch/region. Please send IFSC and branch city.",
            "If this is official, tell me the beneficiary name exactly as it should appear.",
            "Do you have an alternate bank account too? Share alternate account + IFSC.",
        ]
        return _pick_new_excuse(state, bank_lines), {"stage": state.stage}

    # 4) Phone handling: confirm + ask alternate
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        _set_intent(state, "PHONE_PROBE")
        state.phoneAskCount = getattr(state, "phoneAskCount", 0) + 1

        phone_lines = [
            "Which number should I call back? This message came from an unknown sender.",
            "Is this your official support number? Share an alternate helpline too.",
            "I’ll call now. What should I say exactly to verify my account?",
        ]
        return _pick_new_excuse(state, phone_lines), {"stage": state.stage}

    # -------------------------
    # Stage-based extraction sequence (structured and varied)
    # -------------------------

    if state.stage == "HOOK":
        state.stage = "FRICTION"
        _set_intent(state, "HOOK_TO_FRICTION")
        hook_lines = [
            "Why is it getting blocked? What should I do right now?",
            "I don’t understand… what happened to my account?",
            "Is this really SBI? I’m scared. What should I do first?",
        ]
        return _pick_new_excuse(state, hook_lines), {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        _set_intent(state, "FRICTION_TO_EXTRACT")

        friction_lines = [
            "I’m outside and network is weak. Send the verification link and the support number.",
            "Before I do anything, tell me the beneficiary name and IFSC. I don’t want to send to wrong person.",
            "OTP isn’t coming sometimes. Which support number should I call? Send the number.",
            "Send all details in one message: link + UPI or account number + IFSC.",
        ]
        return _pick_new_excuse(state, friction_lines), {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        _set_intent(state, "EXTRACT_TO_VERIFY")

        extract_lines = [
            "Okay. Send link + payment details (UPI or account + IFSC) together.",
            "Send official support number + link. If UPI fails, share bank account + IFSC.",
            "What beneficiary name should appear and what’s the IFSC? Send everything in one message.",
        ]
        return _pick_new_excuse(state, extract_lines), {"stage": state.stage}

    # VERIFY stage: probe missing fields in priority order (avoid repeating same probe)
    if state.stage == "VERIFY":
        _set_intent(state, "VERIFY_PROBE")

        missing_upi = not state.upiIds
        missing_bank = not state.bankAccounts
        missing_ifsc = not state.ifscCodes
        missing_benef = not state.beneficiaryNames
        missing_phone = not state.phoneNumbers
        missing_link = not state.phishingLinks

        probes = []

        # Priority probes (only add if missing)
        if missing_link and state.linkAskCount < 2:
            probes.append("I didn’t get the full link. Paste the complete verification URL once (no spaces).")
        if missing_upi and state.upiAskCount < 2:
            probes.append("If link fails, give me your UPI ID and the beneficiary name that should show in the app.")
        if missing_bank and state.bankAskCount < 2:
            probes.append("If UPI fails, share bank account number + IFSC + branch city.")
        if (missing_ifsc or missing_benef) and (state.ifscAskCount < 2 or state.beneficiaryAskCount < 2):
            probes.append("My app asks IFSC + beneficiary name. Share IFSC and the exact beneficiary name.")
        if missing_phone and state.phoneAskCount < 2:
            probes.append("OTP isn’t coming. Which support number should I call? Send the helpline number.")

        # Human realism fillers (varied)
        probes += [
            "The page is asking security questions. Is that normal? Tell me the exact steps.",
            "Can you send a screenshot of what I should see on the verification page?",
            "I’m using my mother’s phone, OTP comes late sometimes. What’s the OTP time limit?",
        ]

        # Update counters when we pick certain probes
        chosen = _pick_new_excuse(state, probes)
        if "full link" in chosen.lower() or "verification url" in chosen.lower():
            state.linkAskCount = min(getattr(state, "linkAskCount", 0) + 1, 99)
        if "upi id" in chosen.lower():
            state.upiAskCount = min(getattr(state, "upiAskCount", 0) + 1, 99)
        if "bank account" in chosen.lower():
            state.bankAskCount = min(getattr(state, "bankAskCount", 0) + 1, 99)
        if "ifsc" in chosen.lower():
            state.ifscAskCount = min(getattr(state, "ifscAskCount", 0) + 1, 99)
        if "beneficiary" in chosen.lower():
            state.beneficiaryAskCount = min(getattr(state, "beneficiaryAskCount", 0) + 1, 99)
        if "support number" in chosen.lower() or "helpline" in chosen.lower():
            state.phoneAskCount = min(getattr(state, "phoneAskCount", 0) + 1, 99)

        return chosen, {"stage": state.stage}

    # Fallback
    state.stage = "VERIFY"
    _set_intent(state, "FALLBACK")
    return "Can you resend the details clearly once? (link + payment info)", {"stage": state.stage}
