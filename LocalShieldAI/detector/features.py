import re

URL_RE = re.compile(
    r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|in|xyz|top|info|biz|cc|ly|link|click)\b\S*)",
    re.IGNORECASE,
)
URGENCY = ("urgent", "immediately", "act now", "expires", "last chance",
           "within 24", "suspended", "blocked", "verify now", "confirm now")
MONEY = ("won", "winner", "prize", "reward", "cashback", "lottery",
         "free", "claim", "refund", "loan")
CREDENTIALS = ("otp", "pin", "password", "cvv", "kyc", "aadhaar",
               "pan card", "bank account", "upi", "login")


def _hits(text: str, words: tuple) -> list:
    low = text.lower()
    return [w for w in words if w in low]


def sms_warning_signs(text: str) -> list:
    """Return human-readable warning signs found in an SMS."""
    signs = []
    if URL_RE.search(text):
        signs.append("Contains a link")
    if (h := _hits(text, URGENCY)):
        signs.append(f"Urgency or pressure wording: {', '.join(h)}")
    if (h := _hits(text, MONEY)):
        signs.append(f"Money or prize wording: {', '.join(h)}")
    if (h := _hits(text, CREDENTIALS)):
        signs.append(f"Asks about sensitive details: {', '.join(h)}")
    return signs
