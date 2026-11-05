"""Compare the SMS model before and after retraining on the same evaluation files.

    python -m scripts.compare_sms
Uses models/sms_model_before.joblib and models/sms_model.joblib (each with its own thresholds)."""
from pathlib import Path

import pandas as pd

from detector.sms_detector import SmsDetector

ROOT = Path(__file__).resolve().parent.parent
FILES = ["legit_regression.csv", "indian_sms_eval.csv"]
MODELS = {"before": ROOT / "models" / "sms_model_before.joblib",
          "after": ROOT / "models" / "sms_model.joblib"}


def load(name):
    df = pd.read_csv(ROOT / "data" / "eval" / name, on_bad_lines="skip")
    y = df["label"].astype(str).str.lower().map({"0": 0, "1": 1, "ham": 0, "spam": 1})
    return [(str(t), int(v)) for t, v in zip(df["text"], y) if v in (0, 1)]


def main():
    detectors = {k: SmsDetector(p) for k, p in MODELS.items()}
    print("Model versions:", {k: d.meta["model_version"] for k, d in detectors.items()}, "\n")
    for name in FILES:
        rows = load(name)
        n0 = sum(1 for _, y in rows if y == 0)
        n1 = sum(1 for _, y in rows if y == 1)
        print(f"{name}  ({n0} legit, {n1} scam)")
        for k, det in detectors.items():
            fa = fn = 0
            for text, y in rows:
                flagged = det.analyze(text)["risk_level"] != "likely_safe"
                fa += (y == 0 and flagged)
                fn += (y == 1 and not flagged)
            print(f"  {k:6s} legit wrongly flagged: {fa}/{n0}   scams missed: {fn}/{n1}")
        print()


if __name__ == "__main__":
    main()