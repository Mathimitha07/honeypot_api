import re
from typing import Dict, List

# UPI: name@bank (supportdesk@upi, abc.xyz@icici, user-1@okhdfcbank)
UPI_RE = re.compile(r"(?i)\b[a-z0-9][a-z0-9.\-_]{1,}@[a-z]{2,}\b")

# URL: http(s)://... or www....
URL_RE = re.compile(r"(?i)\bhttps?://[^\s]+|\bwww\.[^\s]+\b")

# Indian phone numbers (+91 optional)
PHONE_RE = re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")

# Bank account-like: 9 to 18 digits (avoid 4-6 digit OTPs)
ACCT_RE = re.compile(r"\b\d{9,18}\b")

SUSPICIOUS_WORDS = [
    "urgent", "immediately", "verify", "blocked", "suspended", "click",
    "otp", "kyc", "refund", "cashback", "freeze", "link"
]

def _clean_url(u: str) -> str:
    # Strip common trailing punctuation that appears in messages
    return u.rstrip(").,;!\"'<>]")

def extract_all(text: str) -> Dict[str, List[str]]:
    text = text or ""

    upis = []
    for m in UPI_RE.finditer(text):
        upis.append(m.group(0))

    urls = []
    for m in URL_RE.finditer(text):
        urls.append(_clean_url(m.group(0)))

    phones = []
    for m in PHONE_RE.finditer(text):
        phones.append(m.group(0).replace(" ", "").replace("-", ""))

    accts = []
    for m in ACCT_RE.finditer(text):
        accts.append(m.group(0))

    lower = text.lower()
    keywords = [w for w in SUSPICIOUS_WORDS if w in lower]

    # unique while preserving order
    def uniq(items):
        seen = set()
        out = []
        for x in items:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "upiIds": uniq(upis),
        "phishingLinks": uniq(urls),
        "phoneNumbers": uniq(phones),
        "bankAccounts": uniq(accts),
        "suspiciousKeywords": uniq(keywords),
    }
