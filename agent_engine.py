# agent_engine.py
from typing import Tuple, Dict, Any


from extractor import extract_all


def _pick(state, options):
    """
    Deterministic-ish variety: depends on session personaSeed + turnCount + repeatIntentCount.
    Avoids repeating the same line a lot.
    """
    if not options:
        return ""
    idx = (state.personaSeed + state.turnCount + state.repeatIntentCount) % len(options)
    return options[idx]


def _set_intent(state, intent: str) -> None:
    """
    Track repetition by intent so we don't keep asking the same thing with same wording.
    """
    if state.lastIntent == intent:
        state.repeatIntentCount += 1
    else:
        state.lastIntent = intent
        state.repeatIntentCount = 0


def _use_excuse_once(state, excuse: str) -> str:
    """
    Avoid repeating the exact same excuse text.
    """
    if excuse in state.usedExcuses:
        return ""
    state.usedExcuses.append(excuse)
    return excuse


def _looks_placeholder_name(name: str) -> bool:
    n = (name or "").strip().lower()
    bad = ["john doe", "jane doe", "test", "demo", "sample", "fake", "beneficiary"]
    if any(b in n for b in bad):
        return True
    # too short / too generic
    if len(n) < 4:
        return True
    return False


def next_reply(state, msg_text: str, history, metadata) -> Tuple[str, Dict[str, Any]]:
    extracted = extract_all(msg_text)

    # If already completed, do not loop. Just exit calmly.
    if state.completed:
        state.stage = "EXIT"
        _set_intent(state, "EXIT")
        exit_lines = [
            "Okay, I’m checking now. Please wait a minute.",
            "One minute… app is loading.",
            "Hold on, network is weak here. I’m retrying.",
        ]
        return _pick(state, exit_lines), {"stage": state.stage}

    # -------------------------
    # 0) If we already have enough intel, start exiting naturally
    # -------------------------
    if state.should_complete():
        state.completed = True
        state.stage = "EXIT"
        _set_intent(state, "EXIT")
        exit_lines = [
            "OTP still hasn’t come. I’m calling the bank helpline to complete verification.",
            "My app crashed. I’ll retry after network improves and finish verification.",
            "Network is very weak here. I’ll move outside and complete the verification after that.",
            "I’m going to verify this with the bank directly first. I’ll update you after they confirm.",
        ]
        return _pick(state, exit_lines), {"stage": state.stage}

    # -------------------------
    # 1) React to NEW intel in THIS message (high priority)
    #    Avoid repeating 'resend' loops by switching tactics.
    # -------------------------

    # If beneficiary name appears but looks placeholder -> push for realistic exact name
    if extracted.get("beneficiaryNames"):
        bn = extracted["beneficiaryNames"][-1]
        if _looks_placeholder_name(bn):
            state.stage = "VERIFY"
            _set_intent(state, "ASK_BENEF_REAL")
            lines = [
                "My bank app blocks if the beneficiary name is generic. What *exact full name* will appear on the screen?",
                "That name looks like a placeholder. Tell me the exact beneficiary name as shown in bank (full name).",
                "Please send the beneficiary name exactly as it should appear (not a sample name).",
            ]
            return _pick(state, lines), {"stage": state.stage}

    # If link appears, do progressive variation and force full URL
    if extracted.get("phishingLinks"):
        state.stage = "FRICTION"
        _set_intent(state, "LINK_FRICTION")

        link_tactics = [
            "It opens but shows blank. Paste the full verification link again exactly (not short link).",
            "It says ‘invalid page’ on my phone. Send the full URL again without any extra dots/symbols.",
            "Okay don’t send screenshot. Just paste the exact full link and the steps I should follow.",
            "Send the full link again and the official helpline number in case the link fails.",
        ]
        return _pick(state, link_tactics), {"stage": state.stage}

    # If UPI appears, ask handle/type + beneficiary name + alternate bank
    if extracted.get("upiIds"):
        state.stage = "VERIFY"
        _set_intent(state, "ASK_UPI_DETAILS")

        upi_tactics = [
            "My UPI app shows ‘invalid handle’. Is it @ybl / @okhdfcbank / @upi type? Please confirm the handle part.",
            "Before I proceed, what beneficiary name should show for this UPI on the payment screen?",
            "Google Pay shows ‘name mismatch’. What exact name should appear for this UPI ID?",
            "If UPI fails, can I do bank transfer? Share account number + IFSC + branch city.",
        ]
        return _pick(state, upi_tactics), {"stage": state.stage}

    # If bank account appears, push IFSC + beneficiary + branch
    if extracted.get("bankAccounts"):
        state.stage = "VERIFY"
        _set_intent(state, "ASK_BANK_IFSC")

        bank_tactics = [
            "Okay noted. My bank app needs IFSC + branch city. Please send IFSC and branch/region.",
            "What exact beneficiary name will appear for this account? I don’t want a mismatch.",
            "Send IFSC code + beneficiary name exactly as it should appear, and confirm it’s for verification/unblocking.",
            "Do you have an alternate account/UPI too? Send both so I can try if one fails.",
        ]
        return _pick(state, bank_tactics), {"stage": state.stage}

    # If phone appears, ask for official support + alternate number
    if extracted.get("phoneNumbers"):
        state.stage = "VERIFY"
        _set_intent(state, "ASK_PHONE_CONFIRM")

        phone_tactics = [
            "Is this the official support number? Send the alternate helpline number too.",
            "Okay. What should I say on call to complete verification? Give the exact steps.",
            "If this number is busy, what’s the backup number/WhatsApp support?",
        ]
        return _pick(state, phone_tactics), {"stage": state.stage}

    # -------------------------
    # 2) Stage-based structured extraction sequence (progressive, not repetitive)
    # -------------------------
    if state.stage == "HOOK":
        state.stage = "FRICTION"
        _set_intent(state, "HOOK_TO_FRICTION")
        hook_lines = [
            "Why is it getting blocked? What should I do right now?",
            "I don’t understand… is this really SBI? What’s the next step?",
            "I’m outside and panicking. Tell me what to do step by step.",
        ]
        return _pick(state, hook_lines), {"stage": state.stage}

    if state.stage == "FRICTION":
        state.stage = "EXTRACT"
        _set_intent(state, "FRICTION_TO_EXTRACT")

        # rotate excuses (avoid repeating same one)
        excuse_candidates = [
            "I’m outside, network is weak.",
            "I’m using my mother’s phone, it’s slow.",
            "My UPI app is stuck on loading.",
            "The page is not opening properly on my phone.",
        ]
        excuse = ""
        for ex in excuse_candidates:
            ex2 = _use_excuse_once(state, ex)
            if ex2:
                excuse = ex2
                break

        friction_lines = [
            f"{excuse} Please send the full verification link and the helpline number you want me to call.",
            "Before I do anything, tell me the beneficiary name and IFSC. I don’t want to send to wrong person.",
            "OTP doesn’t seem to come. Which official support number should I call? Send the number.",
            "Send the details in one message: link + UPI (or account+IFSC) + beneficiary name.",
        ]
        return _pick(state, friction_lines), {"stage": state.stage}

    if state.stage == "EXTRACT":
        state.stage = "VERIFY"
        _set_intent(state, "EXTRACT_TO_VERIFY")
        extract_lines = [
            "Okay. Send the full link + payment details (UPI or account + IFSC) together in one message.",
            "Send the official helpline number + full URL. If UPI fails, share bank account + IFSC too.",
            "What beneficiary name should appear and what’s the IFSC? Send everything in one message.",
        ]
        return _pick(state, extract_lines), {"stage": state.stage}

    # VERIFY stage: actively probe missing intel fields with progressive variation
    if state.stage == "VERIFY":
        _set_intent(state, "VERIFY_PROBE")

        missing_link = not state.phishingLinks
        missing_phone = not state.phoneNumbers
        missing_benef = not state.beneficiaryNames
        missing_ifsc = not state.ifscCodes

        probes = []

        # Priority 1: URL
        if missing_link:
            probes += [
                "Screenshot isn’t possible for me. Please paste the full verification link exactly (no short link).",
                "The link isn’t opening. Send the full URL again, without any extra punctuation.",
            ]

        # Priority 2: phone
        if missing_phone:
            probes += [
                "OTP is not coming. Which official support number should I call back right now?",
                "This SMS came from an unknown number. Send the helpline number I should call to verify.",
            ]

        # Priority 3: beneficiary + IFSC
        if missing_benef:
            probes += [
                "My app shows ‘name mismatch’ sometimes. What exact beneficiary name should appear (full name)?",
            ]
        if missing_ifsc:
            probes += [
                "If UPI fails, I’ll do bank transfer. Share account number + IFSC + branch city.",
            ]

        # Additional varied probes
        probes += [
            "The page is asking extra details. What exact steps should I follow to complete verification?",
            "Is the verification time-limited? How many minutes do I have?",
            "I’m going to call the bank first if OTP doesn’t come. Send the official number to call.",
        ]

        return _pick(state, probes), {"stage": state.stage}

    # Fallback
    state.stage = "VERIFY"
    _set_intent(state, "FALLBACK")
    return "Can you resend the details clearly once? (full link + payment info + helpline)", {"stage": state.stage}
