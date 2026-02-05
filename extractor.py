# extractor.py
import re
from typing import Dict, List

# Basic patterns
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

# India phone patterns (10 digits, optional +91, optional spaces/dashes)
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?([6-9]\d{9})")

# UPI id pattern (simple but effective)
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")

# Bank account: keep this STRICT so it doesn't capture phone numbers
# Typical bank account numbers: 11–18 digits (sometimes 9–18, but 10 overlaps with phone).
# We'll use 11–18 to be safe for this hackathon.
BANK_RE = re.compile(r"\b\d{11,18}\b")

# Keywords that hint scam
KEYWORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "kyc", "otp",
    "account", "bank", "limit", "freeze", "locked", "click", "link", "payment"
]


def _unique(xs: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in xs:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def extract_all(text: str) -> Dict[str, List[str]]:
    text = text or ""
    t = text.strip()

    phishing_links = _unique(URL_RE.findall(t))

    # Phone extraction (only the 10-digit core group)
    phones = _unique(PHONE_RE.findall(t))

    # UPI extraction
    upis = _unique(UPI_RE.findall(t))

    # Bank accounts (strict 11-18 digits)
    banks = _unique(BANK_RE.findall(t))

    # Extra safety: if something is detected as phone, don't keep it as bank
    banks = [b for b in banks if b not in phones]

    # Keywords
    lower = t.lower()
    suspicious = _unique([k for k in KEYWORDS if k in lower])

    return {
        "upiIds": upis,
        "bankAccounts": banks,
        "phishingLinks": phishing_links,
        "phoneNumbers": phones,
        "suspiciousKeywords": suspicious
    }
