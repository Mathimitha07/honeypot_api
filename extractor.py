# extractor.py
import re
from typing import Dict, List

# -----------------------
# URL (avoid trailing punctuation like . , ) ] )
# -----------------------
URL_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

# -----------------------
# India phone numbers:
# captures the 10-digit core, optional +91 prefix
# -----------------------
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?([6-9]\d{9})\b")

# -----------------------
# UPI ID
# -----------------------
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")

# -----------------------
# IFSC code (11 chars, 1st 4 letters, 0, then 6 alnum)
# Example: SBIN0001234
# -----------------------
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)

# -----------------------
# Bank account:
# - strict continuous digits 11-18
# - plus a lax spaced/hyphenated pattern that normalizes to 11-18
# -----------------------
BANK_STRICT_RE = re.compile(r"\b\d{11,18}\b")

# Catch sequences like "1234 5678 9012 3456" or "1234-5678-9012-3456"
BANK_LAX_RE = re.compile(r"\b(?:\d[\s-]?){11,22}\b")

# -----------------------
# Beneficiary name patterns (basic but useful)
# e.g., "Beneficiary: Rahul Sharma"
#       "Beneficiary name is 'SBI Support'"
#       "beneficiary will show as SBI Support"
# -----------------------
BENEF_RE = re.compile(
    r"\bbeneficiary(?:\s+name)?\s*(?:is|:|will\s+show\s+as)\s*['\"]?([A-Za-z][A-Za-z\s.\-]{2,40})['\"]?",
    re.IGNORECASE,
)

# Common scam keywords
KEYWORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "kyc", "otp",
    "account", "bank", "limit", "freeze", "locked", "click", "link", "payment",
    "transfer", "fee", "support", "helpline"
]

# punctuation to trim from URLs (fix abc. / abc, / abc) etc.
TRAILING_PUNCT = ".,;:)]}>\"'"


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
    # remove trailing punctuation safely
    if not u:
        return u
    while u and u[-1] in TRAILING_PUNCT:
        u = u[:-1]
    return u


def extract_all(text: str) -> Dict[str, List[str]]:
    text = text or ""
    t = text.strip()
    lower = t.lower()

    # URLs cleaned (fix trailing dot issue)
    phishing_links = [_clean_url(u) for u in URL_RE.findall(t)]
    phishing_links = _unique([u for u in phishing_links if u])

    # Phones (10-digit core)
    phones = _unique(PHONE_RE.findall(t))

    # UPI IDs
    upis = _unique(UPI_RE.findall(t))

    # IFSC codes (normalize upper)
    ifscs = _unique([x.upper() for x in IFSC_RE.findall(t)])

    # Beneficiary names
    beneficiaries = []
    for m in BENEF_RE.findall(t):
        name = (m or "").strip()
        # basic cleanup
        name = re.sub(r"\s+", " ", name)
        if name and len(name) <= 40:
            beneficiaries.append(name)
    beneficiaries = _unique(beneficiaries)

    # Bank accounts
    banks = []

    # 1) strict continuous digits
    banks.extend(BANK_STRICT_RE.findall(t))

    # 2) spaced/hyphenated -> normalize digits -> keep if 11-18 digits
    for raw in BANK_LAX_RE.findall(t):
        d = _digits_only(raw)
        if 11 <= len(d) <= 18:
            banks.append(d)

    banks = _unique(banks)

    # -----------------------
    # Critical safety filters
    # -----------------------

    # (A) never treat phone numbers as bank accounts
    banks = [b for b in banks if b not in phones]

    # (B) never treat "+91" + phone (12 digits like 919876543210) as bank account
    phone12 = {"91" + p for p in phones}
    banks = [b for b in banks if b not in phone12]

    # (C) if a "bank" number is exactly 12 digits and starts with 91, reject (very likely phone)
    banks = [b for b in banks if not (len(b) == 12 and b.startswith("91"))]

    # Keywords
    suspicious = _unique([k for k in KEYWORDS if k in lower])

    return {
        "upiIds": upis,
        "bankAccounts": banks,
        "phishingLinks": phishing_links,
        "phoneNumbers": phones,
        "ifscCodes": ifscs,
        "beneficiaryNames": beneficiaries,
        "suspiciousKeywords": suspicious,
    }
