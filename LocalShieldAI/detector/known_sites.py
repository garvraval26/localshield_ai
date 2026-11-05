"""Built-in list of well-known official sites, checked BEFORE the model.

Safety rules (a known domain can still host a phishing PAGE, so we are strict):
  * only the EXACT address passes: example.com or www.example.com. Other
    subdomains (docs.google.com, sites.google.com ...) go to the detector.
  * links with user info (@), unusual ports, punycode (xn--) or another URL
    hidden inside never pass.
  * shared-hosting and shortener domains are never on the list.
Passing means "this is the real address of a well-known site". It does NOT mean
the page or the message that sent you there is safe.

Your own sites: add one domain or URL per line to data/known_sites.txt."""
import re
from pathlib import Path

from detector.lookalike import BRANDS
from detector.url_features import SHORTENERS, parse_url, registered_domain

KNOWN_FILE = Path(__file__).resolve().parent.parent / "data" / "known_sites.txt"

# Domains where anyone can publish a page: never an instant pass.
NEVER_INSTANT = SHORTENERS | {
    "blogspot.com", "wordpress.com", "github.io", "githubusercontent.com", "weebly.com",
    "wixsite.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "herokuapp.com",
    "firebaseapp.com", "web.app", "appspot.com", "azurewebsites.net", "amazonaws.com",
    "cloudfront.net", "notion.site", "forms.gle", "googleusercontent.com", "sharepoint.com",
    "myshopify.com", "tumblr.com", "000webhostapp.com", "glitch.me", "repl.co",
}
_EMBEDDED_URL = re.compile(r"(https?%3a|https?://|%2f%2f)", re.IGNORECASE)


def load_known(path=KNOWN_FILE):
    """Hand-picked brand domains plus the lines of data/known_sites.txt."""
    domains = {d for ds in BRANDS.values() for d in ds}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip().lower()
            if not line:
                continue
            try:
                host = parse_url(line)[1]
            except ValueError:
                continue
            domains.add(registered_domain(host))
    except OSError:
        pass
    return {d for d in domains if d not in NEVER_INSTANT}


def match_known(parts, host, known):
    """Return the known domain if this link is its exact, plain address; else None."""
    if parts.username is not None or parts.port not in (None, 80, 443):
        return None
    if "xn--" in host:
        return None
    if _EMBEDDED_URL.search((parts.path + "?" + parts.query).lower()):
        return None
    reg = registered_domain(host)
    if reg in known and host in (reg, "www." + reg):
        return reg
    return None