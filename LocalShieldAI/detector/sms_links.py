"""Check the links INSIDE an SMS, and compare them with the company the SMS names.

Pure string rules: no network, no DNS, no redirects followed.

Why: a scam can copy a real company's wording perfectly, but the link has to go to
the scammer's site. "HDFC Bank: verify at http://hdfc-kyc.xyz" names HDFC but the
link is not hdfcbank.com. This only ever RAISES a result; a good link never lowers it.

Limit: only companies in detector/lookalike.py BRANDS are known."""
import re

from detector.features import CREDENTIALS, MONEY, URGENCY, URL_RE, _hits
from detector.known_sites import load_known, match_known
from detector.lookalike import BRANDS, find_lookalike
from detector.url_features import SHORTENERS, parse_url, registered_domain

_TRAIL = ".,;:!?)]}>'\""
MAX_LINKS = 10


def extract_links(text: str) -> list:
    links = []
    for m in URL_RE.finditer(text):
        link = m.group(0).rstrip(_TRAIL)
        if link and link not in links:
            links.append(link)
    return links[:MAX_LINKS]


def brands_mentioned(text: str) -> list:
    low = text.lower()
    return [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", low)]


def check_sms_links(text: str, known=None) -> dict:
    """Return {"links": [...], "signs": [...], "raise": bool}."""
    known = known if known is not None else load_known()
    brands = brands_mentioned(text)
    risky_words = bool(_hits(text, URGENCY) or _hits(text, MONEY) or _hits(text, CREDENTIALS))
    out, signs, raise_level = [], [], False

    for link in extract_links(text):
        try:
            parts, host = parse_url(link)
        except ValueError:
            continue
        reg = registered_domain(host)
        item = {"url": link[:120], "host": host, "status": "other"}
        lk = find_lookalike(host)
        if match_known(parts, host, known):
            item["status"] = "known_site"
        elif lk:
            item["status"] = "lookalike"
            signs.append(f"Link {host}: {lk['sign']}")
            raise_level = True
        elif host in SHORTENERS:
            item["status"] = "shortener"
            signs.append(f"Link {host} is a shortener that hides the real destination")
        elif brands:
            owns = any(reg in BRANDS[b] for b in brands)
            if not owns:
                item["status"] = "brand_mismatch"
                named = ", ".join(brands[:3])
                signs.append(f"Message names {named} but the link goes to {reg}, "
                             "which is not that company's address")
                if risky_words:
                    raise_level = True
        out.append(item)
    return {"links": out, "signs": signs, "raise": raise_level}