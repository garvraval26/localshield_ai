"""URL feature extraction. PURELY STRING-BASED: nothing here opens a
connection, resolves DNS, or follows a redirect."""
import math
import re
from urllib.parse import urlsplit

MAX_URL_LEN = 2048
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rebrand.ly", "ow.ly", "shorturl.at", "tiny.cc"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "icu", "buzz", "cfd", "sbs",
                   "gq", "tk", "ml", "ga", "cf", "work", "support", "zip", "mov"}
KEYWORDS = ("login", "signin", "verify", "secure", "account", "update", "bank",
            "wallet", "kyc", "upi", "password", "confirm", "paypal", "refund",
            "support", "billing", "otp")
TWO_LEVEL = {"co.in", "co.uk", "com.au", "ac.in", "gov.in", "org.in",
             "net.in", "com.br", "co.jp", "co.za"}
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Features the MODEL uses: HOST-ONLY. Why: our legitimate URLs come from a
# domain ranking (no paths) while phishing URLs have paths. Path features would
# let the model learn "has a path = phishing", an artifact of the data.
# Path/query signs are reported as rule-based warnings instead.
MODEL_FEATURES = ["host_len", "num_dots", "num_hyphens", "digit_ratio",
                  "is_ip", "subdomain_depth", "suspicious_tld", "has_punycode",
                  "host_entropy", "host_keyword_count", "has_userinfo"]


class InvalidInputError(ValueError):
    pass


def parse_url(raw: str):
    """Validate and split an untrusted URL string (no network access)."""
    raw = (raw or "").strip()
    if not raw:
        raise InvalidInputError("URL is empty.")
    if len(raw) > MAX_URL_LEN:
        raise InvalidInputError(f"URL is too long (max {MAX_URL_LEN} characters).")
    if re.search(r"\s", raw) or any(ord(c) < 32 for c in raw):
        raise InvalidInputError("URL contains spaces or control characters.")
    if "://" not in raw:
        raw = "http://" + raw  # parsing only; we never connect
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError if the port is malformed
    except ValueError as exc:
        raise InvalidInputError(f"Malformed URL: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise InvalidInputError("Only http and https URLs are accepted.")
    if not host or "." not in host and not IPV4_RE.match(host):
        raise InvalidInputError("URL has no valid host name.")
    return parts, host


def registered_domain(host: str) -> str:
    """Approximate registrable domain (no public-suffix list; documented limit)."""
    if IPV4_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def host_features(host: str, has_userinfo: bool = False) -> dict:
    is_ip = bool(IPV4_RE.match(host))
    labels = host.split(".")
    reg = registered_domain(host)
    sub_depth = 0 if is_ip else max(0, len(labels) - len(reg.split(".")))
    return {
        "host_len": len(host),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "is_ip": int(is_ip),
        "subdomain_depth": sub_depth,
        "suspicious_tld": int(labels[-1] in SUSPICIOUS_TLDS),
        "has_punycode": int("xn--" in host),
        "host_entropy": _entropy(host),
        "host_keyword_count": sum(k in host for k in KEYWORDS),
        "has_userinfo": int(has_userinfo),
    }


def feature_vector(feats: dict) -> list:
    return [float(feats[name]) for name in MODEL_FEATURES]


def url_warning_signs(parts, host: str) -> list:
    """Human-readable, rule-based signs (these also use path/query)."""
    signs = []
    feats = host_features(host, bool(parts.username))
    if feats["is_ip"]:
        signs.append("Uses a raw IP address instead of a domain name")
    if parts.username:
        signs.append("Contains '@' user info, which can hide the real destination")
    if feats["has_punycode"]:
        signs.append("Host uses punycode (xn--), which can imitate look-alike characters")
    if host in SHORTENERS:
        signs.append("Link shortener hides the real destination")
    if feats["suspicious_tld"]:
        signs.append(f"Top-level domain .{host.split('.')[-1]} is often abused")
    if feats["subdomain_depth"] >= 3:
        signs.append("Unusually many subdomain levels")
    if feats["num_hyphens"] >= 3:
        signs.append("Many hyphens in the host name")
    hits = [k for k in KEYWORDS if k in host]
    if hits:
        signs.append(f"Sensitive words in the host name: {', '.join(hits)}")
    tail = (parts.path + "?" + parts.query).lower()
    phits = [k for k in KEYWORDS if k in tail]
    if phits:
        signs.append(f"Sensitive words in the path or query: {', '.join(phits)}")
    if parts.scheme == "http":
        signs.append("Not using HTTPS (traffic is unencrypted)")
    if parts.port not in (None, 80, 443):
        signs.append(f"Unusual port {parts.port}")
    if len(parts.geturl()) > 100:
        signs.append("Very long URL")
    if re.search(r"(https?%3a|https?://)", tail):
        signs.append("Contains another URL inside it (possible redirect trick)")
    return signs
