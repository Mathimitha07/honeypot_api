from typing import Dict, List
import re

STRONG_PATTERNS = [
    r"\baccount\b.*\b(block|blocked|suspend|suspended|freeze|frozen)\b",
    r"\bverify\b.*\b(now|immediately)\b",
    r"\bupi\b|\botp\b|\bkyc\b",
    r"\bclick\b.*\blink\b|\bhttp(s)?://|\bwww\.",
    r"\brefund\b|\bcashback\b|\bloan\b.*\bapproved\b",
    r"\bcustomer\s*care\b|\bhelpline\b",
]

MEDIUM_KEYWORDS = [
    "urgent", "immediately", "today", "final", "limited time",
    "blocked", "suspended", "freeze", "verify", "update kyc"
]

def detect_scam(text: str, history: List[Dict], metadata: Dict) -> Dict:
    t = (text or "").lower()

    strong_hits = sum(1 for pat in STRONG_PATTERNS if re.search(pat, t))
    medium_hits = sum(1 for kw in MEDIUM_KEYWORDS if kw in t)

    scam_prob = min(1.0, 0.45 * strong_hits + 0.12 * medium_hits)

    # Decision: 1 strong OR 3 medium OR prob >= 0.45
    scam_detected = (strong_hits >= 1) or (medium_hits >= 3) or (scam_prob >= 0.45)

    scam_type = "unknown"
    if "upi" in t:
        scam_type = "upi_fraud"
    elif "otp" in t or "kyc" in t:
        scam_type = "bank_kyc"
    elif "http" in t or "www." in t or "link" in t or "click" in t:
        scam_type = "phishing"
    elif "customer care" in t or "helpline" in t:
        scam_type = "helpdesk_impersonation"

    keywords = []
    for kw in ["blocked", "verify", "urgent", "otp", "kyc", "upi", "link", "refund", "cashback"]:
        if kw in t:
            keywords.append(kw)

    return {
        "scamProbability": scam_prob,
        "scamDetected": scam_detected,
        "scamType": scam_type,
        "keywords": keywords
    }
