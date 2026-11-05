"""Validate the Llama reply and build a safe fallback when it is missing or rejected."""
import json
import re

MAX_EXPLANATION = 1200
MAX_ADVICE_ITEMS = 5
MAX_ADVICE_LEN = 300


class LlamaResponseError(ValueError):
    pass


# Claims that must never appear, whatever the detector said.
_ALWAYS_BAD = [r"\b100\s*%\s*safe", r"\bcompletely safe\b",
               r"\btotally safe\b", r"\bdefinitely safe\b", r"\bno risk\b", r"\brisk[- ]free\b"]
# "guaranteed safe" is bad; "this is not a guarantee of safety" is honest and allowed.
_GUARANTEE = re.compile(r"\bguarantee[sd]?\b.{0,20}\bsafe")
# Extra claims that contradict a suspicious / high_risk detector result.
_BAD_WHEN_FLAGGED = [r"\b(is|are|looks|seems|appears)\s+(?!not\b|never\b)(\w+\s+)?(safe|legitimate|genuine|harmless)\b",
                     r"\bnot (a )?(scam|phishing|fraud)\b", r"\bnothing to worry\b",
                     r"\bsafe to (click|open|visit|ignore|reply)\b", r"\bno need to worry\b"]
# Scam claims are wrong when the detector said "likely_safe" (unless negated: "not a scam").
_SCAM_WORDS = re.compile(r"\b(scam|scammers?|phishing|fraud|fraudulent|malicious|dangerous|harmful)\b")
_NEGATION = re.compile(r"\b(not|no|never|without|isn't|doesn't|does not|n't)\b")
# Wrong when the detector said "likely_safe": "not considered safe", "may not be safe", "unsafe".
# (Honest wording such as "this does not prove it is safe" is NOT matched.)
_UNSAFE_CLAIMS = [r"\bunsafe\b",
                  r"\b(isn't|aren't|wasn't|weren't)\s+(considered\s+|deemed\s+|regarded\s+|seen as\s+)?"
                  r"(safe|secure|trustworthy|legitimate)\b",
                  r"\bnot\s+(be\s+)?(considered\s+|deemed\s+|regarded\s+|seen as\s+)?"
                  r"(safe|secure|trustworthy|legitimate)\b"]
# "The message asks for the verification code" is only allowed if the detector found a request.
_CLAIMS_REQUEST = re.compile(
    r"\b(ask|asks|asking|request|requests|requesting|demand|demands|wants?)\b[^.]{0,60}?"
    r"\b(otp|pin|password|cvv|verification code|code|login details|credentials|card number)\b")
# Advice that tells the user to do something risky.
_BAD_ADVICE = [r"\b(click|tap|open|visit)\b.{0,25}\b(the|this)\s+(link|url|website|site)\b",
               r"\b(reply|respond)\b.{0,15}\b(to the|to this)\b"]


def _extract_json(raw: str) -> dict:
    raw = (raw or "").strip()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise LlamaResponseError("reply is not JSON")
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError as exc:
            raise LlamaResponseError("reply is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise LlamaResponseError("reply is not a JSON object")
    return obj


def validate_response(raw: str, risk_level: str, signs=None) -> dict:
    """Return {'explanation', 'advice'} or raise LlamaResponseError.
    signs: the detector's warning signs (optional). When given, the reply may only say the
    message "asks for" a code/password if the detector actually found such a request."""
    obj = _extract_json(raw)
    expl, advice = obj.get("explanation"), obj.get("advice")
    if not isinstance(expl, str) or not expl.strip():
        raise LlamaResponseError("missing explanation")
    if len(expl) > MAX_EXPLANATION:
        raise LlamaResponseError("explanation too long")
    if (not isinstance(advice, list) or not 1 <= len(advice) <= MAX_ADVICE_ITEMS
            or not all(isinstance(a, str) and a.strip() and len(a) <= MAX_ADVICE_LEN for a in advice)):
        raise LlamaResponseError("advice must be 1-5 short strings")
    text = (expl + " " + " ".join(advice)).lower()
    for m in _GUARANTEE.finditer(text):
        if not _NEGATION.search(text[max(0, m.start() - 40):m.start()]):
            raise LlamaResponseError("reply contradicts the detector result")
    bad = list(_ALWAYS_BAD) + (_BAD_WHEN_FLAGGED if risk_level in ("suspicious", "high_risk") else [])
    for pat in bad:
        if re.search(pat, text):
            raise LlamaResponseError("reply contradicts the detector result")
    if risk_level == "likely_safe":
        for pat in _UNSAFE_CLAIMS:
            if re.search(pat, text):
                raise LlamaResponseError("reply says a likely_safe result is not safe")
        for m in _SCAM_WORDS.finditer(text):
            if not _NEGATION.search(text[max(0, m.start() - 40):m.start()]):
                raise LlamaResponseError("reply calls a likely_safe result a scam")
    if signs is not None and not any(str(x).startswith("Asks you") for x in signs):
        if _CLAIMS_REQUEST.search(text):
            raise LlamaResponseError("reply claims a request that the detector did not find")
    for a in advice:
        low = a.lower()
        if re.search(r"\b(not|never|don't|dont|avoid|without)\b", low):
            continue  # a warning such as "Do not click the link" is good advice
        for pat in _BAD_ADVICE:
            if re.search(pat, low):
                raise LlamaResponseError("advice tells the user to interact with the content")
    return {"explanation": expl.strip(), "advice": [a.strip() for a in advice]}


_ADVICE = {
    "url": ["Do not open this link.", "If you think it is real, type the company's official web address yourself.",
            "Never enter passwords, OTPs or card details on a page you reached from a message."],
    "sms": ["Do not click any link in this message or reply to it.",
            "Contact the organisation using the number on its official website or your card.",
            "Never share OTPs, PINs or passwords with anyone who contacts you."],
}


def fallback_response(result: dict) -> dict:
    """Plain template used when Llama is unavailable or its reply was rejected."""
    kind = "URL" if result.get("type") == "url" else "message"
    level = result.get("risk_level")
    score = result.get("score")
    signs = result.get("warning_signs") or []
    label = {"high_risk": "HIGH RISK", "suspicious": "SUSPICIOUS"}.get(level, "LOW RISK")
    text = f"The detector rates this {kind} as {label} (score {score}, an estimate and not a probability)."
    if signs:
        text += " Warning signs: " + "; ".join(signs[:5]) + "."
    if level == "likely_safe":
        text += " Few warning signs were found, but this does not prove it is safe."
    return {"explanation": text, "advice": list(_ADVICE["url" if result.get("type") == "url" else "sms"])}