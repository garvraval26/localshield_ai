"""Decides whether the user's text is a URL or an SMS. Pure text checks, no network."""
import re

MAX_INPUT_LEN = 2048

# One token that starts with http(s):// or looks like domain.tld[/path]
_URL_LIKE = re.compile(
    r"^(https?://\S+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?)$", re.IGNORECASE
)


def detect_input(text, forced=None):
    """Return {ok, kind, text, note, message}.

    forced: None (auto-detect), "url" or "sms" (manual override from the UI).
    """
    if forced not in (None, "url", "sms"):
        raise ValueError("forced must be None, 'url' or 'sms'")

    value = (text or "").strip()
    if not value:
        return {"ok": False, "kind": None, "text": "", "note": None,
                "message": "Please paste a link or a message first."}
    if len(value) > MAX_INPUT_LEN:
        return {"ok": False, "kind": None, "text": "", "note": None,
                "message": f"Input is too long (max {MAX_INPUT_LEN} characters)."}

    kind = forced or ("url" if _URL_LIKE.match(value) else "sms")
    note = None

    if kind == "url":
        if re.search(r"\s", value):
            return {"ok": False, "kind": "url", "text": value, "note": None,
                    "message": "A link cannot contain spaces. Check it, or switch to the SMS tab."}
        if not re.match(r"^https?://", value, re.IGNORECASE):
            value = "http://" + value
            note = "No http:// or https:// was given, so http:// was added for analysis only."
        elif not re.match(r"^https?://\S", value, re.IGNORECASE):
            return {"ok": False, "kind": "url", "text": value, "note": None,
                    "message": "That link looks incomplete."}

    return {"ok": True, "kind": kind, "text": value, "note": note, "message": "OK"}