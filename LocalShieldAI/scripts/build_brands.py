"""Build models/brands.json from the Tranco list you already downloaded.

Run once (needs data/raw/tranco.csv from scripts/download_url_data.py):
    python -m scripts.build_brands

The file is used by detector/lookalike.py:
  top_brands  - the most popular sites: lookalike targets
  known_legit - the top sites overall: never flagged as lookalikes
Everything stays on this computer. Nothing is fetched here."""
import json
from datetime import date
from pathlib import Path

from detector.url_features import registered_domain

ROOT = Path(__file__).resolve().parent.parent
TRANCO = ROOT / "data" / "raw" / "tranco.csv"
OUT = ROOT / "models" / "brands.json"
TOP_BRANDS = 1500
KNOWN_LEGIT = 100_000


def main():
    if not TRANCO.exists():
        raise SystemExit(f"{TRANCO} not found. Run: python -m scripts.download_url_data")
    seen, ordered = set(), []
    with TRANCO.open(encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 2:
                continue
            dom = registered_domain(parts[1].strip().lower())
            if dom and "." in dom and dom not in seen:
                seen.add(dom)
                ordered.append(dom)
            if len(ordered) >= KNOWN_LEGIT:
                break
    data = {"source": "Tranco top sites list", "built": date.today().isoformat(),
            "top_brands": ordered[:TOP_BRANDS], "known_legit": ordered}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(data), encoding="utf-8")
    print(f"Saved {OUT}: {len(data['top_brands'])} brands, {len(ordered)} known-real domains")


if __name__ == "__main__":
    main()