"""One-time SETUP script. Downloads the UCI SMS Spam Collection (CC BY 4.0).
The application never calls this at runtime."""
import io
import urllib.request
import zipfile
from pathlib import Path

URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
OUT = Path(__file__).resolve().parent.parent / "data" / "raw"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {URL} ...")
    with urllib.request.urlopen(URL, timeout=60) as resp:
        payload = resp.read()
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        zf.extract("SMSSpamCollection", OUT)
    print(f"Saved to {OUT / 'SMSSpamCollection'}")


if __name__ == "__main__":
    main()
