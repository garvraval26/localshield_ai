"""Prove the portable (no scikit-learn) models match the real scikit-learn models on YOUR data.

    python -m scripts.export_portable      # first, write models/*_model.json
    python -m scripts.check_portable

SMS: every message in the UCI file, data/eval/*.csv and data/train_extra/*.csv.
URL: every phishing URL and the first 5000 Tranco hosts.
Prints the largest score difference and how many risk levels differ (must be 0)."""
import csv
import json
import sys
from pathlib import Path

import joblib

from detector.portable import load_model
from detector.url_features import InvalidInputError, feature_vector, host_features, parse_url

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"
DATA = ROOT / "data"


def level(score, meta):
    return ("high_risk" if score >= meta["high_risk_at"]
            else "suspicious" if score >= meta["suspicious_at"] else "likely_safe")


def sms_texts(data_dir=DATA):
    texts = []
    uci = data_dir / "raw" / "SMSSpamCollection"
    if uci.exists():
        for line in uci.read_text(encoding="latin-1").splitlines():
            if "\t" in line:
                texts.append(line.split("\t", 1)[1])
    for folder in ("eval", "train_extra"):
        for f in sorted((data_dir / folder).glob("*.csv")) if (data_dir / folder).exists() else []:
            with open(f, encoding="utf-8", newline="") as fh:
                for row in csv.DictReader(fh):
                    t = row.get("text") or row.get("message") or row.get("v2")
                    if t:
                        texts.append(t)
    return texts


def url_vectors(data_dir=DATA):
    hosts = []
    ph = data_dir / "raw" / "phishing_urls.txt"
    if ph.exists():
        hosts += [u.strip() for u in ph.read_text(encoding="utf-8", errors="ignore").splitlines() if u.strip()]
    tr = data_dir / "raw" / "tranco.csv"
    if tr.exists():
        with open(tr, encoding="utf-8") as fh:
            for i, row in enumerate(csv.reader(fh)):
                if i >= 5000:
                    break
                if row:
                    hosts.append("https://" + row[-1].strip())
    rows = []
    for u in hosts:
        try:
            parts, host = parse_url(u)
        except InvalidInputError:
            continue
        rows.append(feature_vector(host_features(host, bool(parts.username))))
    return rows


def compare(name, real, plain, items, meta):
    want = [p[1] for p in real.predict_proba(items)]
    got = [p[1] for p in plain.predict_proba(items)]
    diff = max((abs(a - b) for a, b in zip(want, got)), default=0.0)
    flips = sum(level(a, meta) != level(b, meta) for a, b in zip(want, got))
    ok = diff < 1e-9 and flips == 0
    print(f"{name}: {len(items)} items, max score difference {diff:.2e}, "
          f"risk levels that differ: {flips}  ->  {'MATCH' if ok else 'MISMATCH'}")
    return ok


def main() -> int:
    ok = True
    for name, items in (("sms", sms_texts()), ("url", url_vectors())):
        jl, js = MODELS / f"{name}_model.joblib", MODELS / f"{name}_model.json"
        if not jl.exists() or not js.exists():
            print(f"{name}: missing {jl.name} or {js.name} (run scripts.export_portable)")
            ok = False
            continue
        meta = json.loads((MODELS / f"{name}_meta.json").read_text(encoding="utf-8"))
        ok &= compare(name, joblib.load(jl), load_model(js), items, meta)
    print("\nALL MATCH" if ok else "\nNOT SAFE TO USE ON THE PHONE YET")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())