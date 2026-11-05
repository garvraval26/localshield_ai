"""Look-alike (typosquatting / brand impersonation) check. PURELY STRING-BASED:
no network, no DNS. A rule layer on top of the ML model, which cannot see misspellings.

Two sources of brands:
  1. BRANDS below: a hand-picked list of high-risk brands (banks, payments, big
     tech, delivery, crypto). Used for the strict rules, including "brand name
     inside a fake domain" (paytm-kyc-update.xyz).
  2. models/brands.json (built by scripts/build_brands.py from the Tranco list):
     the top ~1500 sites as typo targets and the top 100,000 sites as a
     "known real" list that is never flagged. If the file is missing, only the
     hand-picked list is used.

Limits (documented): a brand that is on neither list is not protected; a real
small site one typo away from a famous name can still be flagged. This rule layer
only ever raises a result to "suspicious", never "high_risk"."""
import json
from pathlib import Path

from detector.url_features import SUSPICIOUS_TLDS, TWO_LEVEL, registered_domain

BRANDS_FILE = Path(__file__).resolve().parent.parent / "models" / "brands.json"

# brand label -> registered domains that really belong to it (check before relying)
BRANDS = {
    "google": ["google.com", "google.co.in", "google.in"],
    "gmail": ["gmail.com"],
    "youtube": ["youtube.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "flipkart": ["flipkart.com"],
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "yahoo": ["yahoo.com"],
    "outlook": ["outlook.com"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com"],
    "zoom": ["zoom.us"],
    "telegram": ["telegram.org"],
    "snapchat": ["snapchat.com"],
    "tiktok": ["tiktok.com"],
    "spotify": ["spotify.com"],
    "ebay": ["ebay.com"],
    "alibaba": ["alibaba.com"],
    "aliexpress": ["aliexpress.com"],
    "walmart": ["walmart.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "myntra": ["myntra.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "meesho": ["meesho.com"],
    "uber": ["uber.com"],
    "airtel": ["airtel.in", "airtel.com"],
    "jio": ["jio.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"],
    "hdfc": ["hdfc.com", "hdfcbank.com", "hdfclife.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "yesbank": ["yesbank.in"],
    "indusind": ["indusind.com"],
    "idfcfirstbank": ["idfcfirstbank.com"],
    "canarabank": ["canarabank.com"],
    "pnbindia": ["pnbindia.in"],
    "bankofbaroda": ["bankofbaroda.in", "bankofbaroda.com"],
    "bajajfinserv": ["bajajfinserv.in"],
    "zerodha": ["zerodha.com"],
    "groww": ["groww.in"],
    "citibank": ["citibank.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "americanexpress": ["americanexpress.com"],
    "mastercard": ["mastercard.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "bluedart": ["bluedart.com"],
    "indiapost": ["indiapost.gov.in"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "npci": ["npci.org.in"],
    "incometax": ["incometax.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "parivahan": ["parivahan.gov.in"],
}


def _load_data(path=BRANDS_FILE):
    """Return (top_brands list, known_legit set). Empty if the file is missing."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return list(data.get("top_brands", [])), set(data.get("known_legit", []))
    except (OSError, ValueError):
        return [], set()


def data_status():
    """For the UI/README: is the large brand list loaded?"""
    return {"loaded": bool(_TOP), "top_brands": len(_TOP), "known_real": len(_KNOWN)}


_TOP, _KNOWN = _load_data()
_CURATED = {d for domains in BRANDS.values() for d in domains}
_LEGIT = _CURATED | _KNOWN
_TARGETS = sorted(d for d in _CURATED if len(d) >= 8)          # strict list
_TOP_TARGETS = [d for d in _TOP if len(d) >= 10 and d not in _CURATED]
_TOP_LABELS = {}
for _d in _TOP:
    _lab = _d.split(".")[0]
    if len(_lab) >= 8 and _lab not in BRANDS:
        _TOP_LABELS.setdefault(_lab, _d)

_SUBS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Edit distance where swapping two neighbouring letters counts as ONE edit
    (aitrel -> airtel). Returns limit+1 when it is clearly larger than limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                best = min(best, prev2[j - 2] + 1)
            cur.append(best)
        prev2, prev = prev, cur
    return min(prev[-1], limit + 1)


def _normalise(label: str) -> list:
    """Undo common look-alike tricks: digits for letters, 'rn' for 'm', 'vv' for 'w'."""
    base = label.translate(_SUBS).replace("rn", "m").replace("vv", "w")
    variants = {base}
    if "1" in label:  # '1' can stand for 'i' as well as 'l'
        variants.add(label.translate(_SUBS | {ord("1"): "i"}).replace("rn", "m"))
    return list(variants)


def _hit(brand, real, sign):
    return {"brand": brand, "real_domain": real, "sign": sign}


def find_lookalike(host: str):
    """Return None, or {"brand", "real_domain", "sign"} for the first rule that matches."""
    host = host.lower().strip(".")
    reg = registered_domain(host)
    if reg in _LEGIT:
        return None  # a genuine, known domain (or a subdomain of it)

    label, suffix = reg.split(".", 1)
    suspicious_tld = reg.split(".")[-1] in SUSPICIOUS_TLDS

    # 1. Digit / letter swaps: g00gle.com, paypa1.com, rnicrosoft.com
    for variant in _normalise(label):
        if variant == label:
            continue
        if variant in BRANDS:
            real = BRANDS[variant][0]
        elif variant in _TOP_LABELS:
            real = _TOP_LABELS[variant]
        else:
            continue
        return _hit(variant, real, f"Imitates {real} using look-alike characters ('{label}')")

    # 2. One typo away from a real domain: gooogle.com, gogle.com, hdfcbank.co
    for target in _TARGETS + _TOP_TARGETS:
        if _edit_distance(reg, target, 1) == 1:
            return _hit(target.split(".")[0], target, f"Looks like a misspelling of {target}")

    # 3. Name and ending checked separately, so typos in BOTH still match:
    #    gooogle.cooom, gooogle.org, google.cooom   (hand-picked brands)
    for brand, domains in BRANDS.items():
        if len(brand) < 5:
            continue
        limit = 1 if len(brand) <= 7 else 2
        d = _edit_distance(label, brand, limit)
        if d > limit:
            continue
        real_suffixes = {x.split(".", 1)[1] for x in domains}
        close_suffix = suspicious_tld or any(
            _edit_distance(suffix, rs, 2) <= 2 for rs in real_suffixes)
        if d > 0:
            # a misspelt name (6+ letters) is suspicious on any ending; shorter
            # names only when the ending also looks like the real one
            if len(brand) >= 6 or close_suffix:
                return _hit(brand, domains[0], f"Looks like a misspelling of {domains[0]}")
        elif close_suffix and suffix not in TWO_LEVEL and suffix not in real_suffixes:
            # exact name with a garbled ending: google.cooom (not google.co.in, google.org)
            if suspicious_tld or _edit_distance(suffix, "com", 2) <= 2:
                return _hit(brand, domains[0], f"Looks like a misspelling of {domains[0]}")

    # 3b. Same idea for the big list, but stricter: 8+ letter names, one typo,
    #     and an ending that matches or is one typo from the real one.
    for lab, real in _TOP_LABELS.items():
        if _edit_distance(label, lab, 1) == 1:
            real_suffix = real.split(".", 1)[1]
            if _edit_distance(suffix, real_suffix, 1) <= 1:
                return _hit(lab, real, f"Looks like a misspelling of {real}")

    # 4. A real brand name added to someone else's domain: paytm-kyc-update.xyz,
    #    paytm.verify-now.xyz, sbi-secure-login.com   (hand-picked brands only)
    sub_labels = host.split(".")[: -len(reg.split("."))]
    for brand, domains in BRANDS.items():
        if len(brand) < 3:
            continue
        in_name = label != brand and brand in label.split("-")
        in_subdomain = brand in sub_labels
        on_bad_tld = label == brand and suspicious_tld
        if in_name or in_subdomain or on_bad_tld:
            return _hit(brand, domains[0], f"Uses the name '{brand}' but is not {domains[0]}")

    # 4b. A real domain written inside a longer host: paytm.com.verify-now.xyz
    dotted = "." + host + "."
    for d in _TARGETS + _TOP_TARGETS[:500]:
        if f".{d}." in dotted and host != d and not host.endswith("." + d):
            return _hit(d.split(".")[0], d, f"Contains '{d}' inside a different domain")
    return None