# extractor.py
import re
from typing import Dict, List

# -----------------------------
# Regex patterns
# -----------------------------

# URLs (simple + effective)
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

# India phone pattern:
# - 10-digit mobile numbers starting 6-9
# - optional +91 prefix
# - IMPORTANT: prevent matching inside longer digit strings (fixes bank→phone false positives)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{9})(?!\d)")

# UPI id pattern
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")

# Strict continuous digits bank account (11-18 digits)
BANK_RE = re.compile(r"\b\d{11,18}\b")

# Also catch spaced/hyphenated digit sequences that become 11-18 digits after cleanup
# Example: "1234 5678 9012 3456" -> "1234567890123456"
# We allow up to 22 chars because of spaces/hyphens between digits.
BANK_LAX_RE = re.compile(r"\b(?:\d[\s-]?){11,22}\b")

KEYWORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "kyc", "otp",
    "account", "bank", "limit", "freeze", "locked", "click", "link", "payment"
]


# -----------------------------
# Helpers
# -----------------------------
def _unique(xs: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in xs:
        if not x:
            continue
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _digits_only(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


# -----------------------------
# Main extraction
# -----------------------------
def extract_all(text: str) -> Dict[str, List[str]]:
    t = (text or "").strip()

    phishing_links = _unique(URL_RE.findall(t))

    # Phones: keep only the 10-digit core group
    phones = _unique(PHONE_RE.findall(t))

    # UPI IDs
    upis = _unique(UPI_RE.findall(t))

    # Bank accounts
    banks: List[str] = []

    # 1) continuous 11-18 digit sequences
    banks.extend(BANK_RE.findall(t))

    # 2) spaced/hyphenated candidates -> normalize -> keep if 11-18 digits
    for raw in BANK_LAX_RE.findall(t):
        d = _digits_only(raw)
        if 11 <= len(d) <= 18:
            banks.append(d)

    banks = _unique(banks)

    # Extra safety: never keep a phone number as a bank account
    banks = [b for b in banks if b not in phones]

    # Keywords
    lower = t.lower()
    suspicious = _unique([k for k in KEYWORDS if k in lower])

    return {
        "upiIds": upis,
        "bankAccounts": banks,
        "phishingLinks": phishing_links,
        "phoneNumbers": phones,
        "suspiciousKeywords": suspicious,
    }
