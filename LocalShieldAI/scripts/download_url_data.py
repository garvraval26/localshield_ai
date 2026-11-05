"""One-time SETUP script (the app never downloads anything).
- Phishing URLs: OpenPhish community feed (free, check their terms of use:
  intended for non-commercial/research use). Appends + dedupes, so you can run
  it on different days to grow the dataset.
- Legitimate domains: Tranco research ranking (top 1M)."""
import io
import urllib.request
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "raw"
OPENPHISH = "https://openphish.com/feed.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "LocalShieldAI-setup"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    # Strings only; these URLs are never visited.
    new = [l.strip() for l in fetch(OPENPHISH).decode("utf-8", "replace").splitlines() if l.strip()]
    target = OUT / "phishing_urls.txt"
    old = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    merged = sorted(set(old) | set(new))
    target.write_text("\n".join(merged) + "\n", encoding="utf-8")
    print(f"phishing_urls.txt: {len(merged)} URLs ({len(merged) - len(set(old))} new)")
    with zipfile.ZipFile(io.BytesIO(fetch(TRANCO))) as zf:
        (OUT / "tranco.csv").write_bytes(zf.read(zf.namelist()[0]))
    print("tranco.csv saved")


if __name__ == "__main__":
    main()
