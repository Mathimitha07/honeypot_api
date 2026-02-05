# extractor.py
import re
from typing import Dict, List

# -----------------------------
# Regex patterns
# -----------------------------

# URLs (extract then clean trailing punctuation)
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

# India phone pattern:
# - capture 10-digit mobile numbers starting 6-9
# - optional +91 prefix with spaces/dashes
# - avoid matching inside longer digit strings
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{9})(?!\d)")

# UPI id pattern
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")

# Strict continuous digits bank account (11-18 digits)
BANK_RE = re.compile(r"\b\d{11,18}\b")

# Catch spaced/hyphenated digit sequences that become 11-18 digits after cleanup
# Example: "1234 5678 9012 3456" -> "1234567890123456"
BANK_LAX_RE = re.compile(r"\b(?:\d[\s-]?){11,22}\b")

KEYWORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "kyc", "otp",
    "account", "bank", "limit", "freeze", "locked", "click", "link", "payment"
]

# Characters we should strip from the end of extracted URLs
URL_TRAIL_CHARS = ".,);:!?]}>\"'"


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


def _clean_url(u: str) -> str:
    return (u or "").rstrip(URL_TRAIL_CHARS)


# -----------------------------
# Main extraction
# -----------------------------
def extract_all(text: str) -> Dict[str, List[str]]:
    t = (text or "").strip()

    # URLs + cleanup trailing punctuation
    phishing_links = _unique([_clean_url(u) for u in URL_RE.findall(t)])

    # Phones: keep only the 10-digit core group
    phones = _unique(PHONE_RE.findall(t))

    # UPI IDs
    upis = _unique(UPI_RE.findall(t))

    # Banks
    banks: List[str] = []

    # 1) continuous 11-18 digit sequences
    banks.extend(BANK_RE.findall(t))

    # 2) spaced/hyphenated sequences -> normalize -> keep if 11-18 digits
    for raw in BANK_LAX_RE.findall(t):
        d = _digits_only(raw)
        if 11 <= len(d) <= 18:
            banks.append(d)

    banks = _unique(banks)

    # -----------------------------
    # Critical fix:
    # Remove phone numbers mistakenly captured as banks.
    # This specifically catches +91XXXXXXXXXX -> 91XXXXXXXXXX (12 digits)
    # -----------------------------
    filtered_banks = []
    for b in banks:
        # If bank candidate is "91" + <phone10>, drop it
        if len(b) == 12 and b.startswith("91") and b[2:] in phones:
            continue
        # Extra safety: never keep a pure 10-digit phone as bank
        if b in phones:
            continue
        filtered_banks.append(b)

    banks = filtered_banks

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
