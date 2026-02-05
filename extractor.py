# extractor.py
import re
from typing import Dict, List

# URLs (we will strip trailing punctuation)
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

# India phone: capture core 10-digit mobile starting 6-9 (optional +91 prefix)
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?([6-9]\d{9})")

# UPI id
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")

# IFSC: 4 letters + 0 + 6 alnum (e.g., SBIN0001234)
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# Bank account strict (continuous digits 11-18)
BANK_RE = re.compile(r"\b\d{11,18}\b")

# Lax bank: spaced/hyphenated digits -> normalize and validate length
# Example: "1234 5678 9012 3456" -> "1234567890123456"
BANK_LAX_RE = re.compile(r"\b(?:\d[\s-]?){11,22}\b")

# Beneficiary name patterns (simple but useful)
# Captures after "beneficiary:" / "beneficiary name is" / "name will show as"
BENEF_RE = re.compile(
    r"\b(?:beneficiary(?:\s+name)?|name)\s*(?:is|:|will\s*show\s*as)\s*['\"]?([A-Za-z][A-Za-z .]{1,50})['\"]?",
    re.IGNORECASE,
)

KEYWORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "kyc", "otp",
    "account", "bank", "limit", "freeze", "locked", "click", "link", "payment"
]


def _unique(xs: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in xs:
        x = (x or "").strip()
        if not x:
            continue
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _digits_only(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


def _clean_url(u: str) -> str:
    # remove trailing punctuation like . , ; ) ]
    return (u or "").rstrip(").,;]>\"'")


def extract_all(text: str) -> Dict[str, List[str]]:
    t = (text or "").strip()
    lower = t.lower()

    # URLs (clean)
    phishing_links = _unique([_clean_url(u) for u in URL_RE.findall(t)])

    # Phones (10-digit core)
    phones = _unique(PHONE_RE.findall(t))
    phone_set = set(phones)

    # UPI IDs
    upis = _unique(UPI_RE.findall(t))

    # IFSC codes (normalize to uppercase)
    ifscs = _unique([m.group(0).upper() for m in IFSC_RE.finditer(t.upper())])

    # Beneficiary names (FIXED variable + better cleanup)
    beneficiary = []
    for m in BENEF_RE.finditer(t):
        name = (m.group(1) or "").strip()

        # Cleanup: stop at common trailing fields
        name = re.split(r"\b(?:ifsc|upi|account|otp|link)\b", name, flags=re.IGNORECASE)[0].strip()
        name = name.strip(" -:,;")

        # Avoid capturing overly short / generic junk
        if len(name) >= 2 and len(name) <= 50:
            beneficiary.append(name)

    beneficiary = _unique(beneficiary)

    # Bank accounts:
    banks = []

    # 1) continuous digits (11-18)
    banks += BANK_RE.findall(t)

    # 2) spaced/hyphenated -> normalize -> keep 11-18
    for raw in BANK_LAX_RE.findall(t):
        d = _digits_only(raw)
        if 11 <= len(d) <= 18:
            banks.append(d)

    banks = _unique(banks)

    # Remove anything that is actually a phone number in disguise:
    # - never keep 10-digit phones as bank
    # - if 12 digits startswith 91 and last10 is a phone, drop it (e.g., 919876543210)
    cleaned_banks = []
    for b in banks:
        if len(b) == 10 and b in phone_set:
            continue
        if len(b) == 12 and b.startswith("91") and b[-10:] in phone_set:
            continue
        cleaned_banks.append(b)
    banks = cleaned_banks

    # Keywords
    suspicious = _unique([k for k in KEYWORDS if k in lower])

    return {
        "upiIds": upis,
        "bankAccounts": banks,
        "phishingLinks": phishing_links,
        "phoneNumbers": phones,
        "ifscCodes": ifscs,
        "beneficiaryNames": beneficiary,
        "suspiciousKeywords": suspicious,
    }
