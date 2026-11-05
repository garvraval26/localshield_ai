"""Score every message in a CSV (label,text) with the current SMS model.

    python -m scripts.check_sms                              # the 6 legit regression messages
    python -m scripts.check_sms data/eval/indian_sms_eval.csv
Labels: 0/1 or ham/spam. Prints each message's score and level and the error counts."""
import sys
from pathlib import Path

import pandas as pd

from detector.sms_detector import SmsDetector

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "data" / "eval" / "legit_regression.csv"


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    df = pd.read_csv(path, on_bad_lines="skip")
    cols = {str(c).lower(): c for c in df.columns}
    lab = cols.get("label") or cols.get("v1") or df.columns[0]
    txt = cols.get("text") or cols.get("message") or cols.get("v2") or df.columns[1]
    y = df[lab].astype(str).str.lower().map({"0": 0, "1": 1, "ham": 0, "spam": 1})
    det = SmsDetector()
    fa = fn = n0 = n1 = 0
    print(f"Model {det.meta['model_version']}  suspicious_at={det.meta['suspicious_at']}  "
          f"high_risk_at={det.meta['high_risk_at']}\n")
    for text, truth in zip(df[txt], y):
        if truth not in (0, 1):
            continue
        r = det.analyze(str(text))
        flagged = r["risk_level"] != "likely_safe"
        n0 += truth == 0
        n1 += truth == 1
        bad = (truth == 0 and flagged) or (truth == 1 and not flagged)
        fa += truth == 0 and flagged
        fn += truth == 1 and not flagged
        if len(df) <= 60 or bad:
            mark = "WRONG" if bad else "ok   "
            print(f"{mark} {r['score']:.2f} {r['risk_level']:12s} [{'scam' if truth else 'legit'}] "
                  f"{str(text)[:90]}")
    print(f"\nLegit messages wrongly flagged: {fa} of {n0}")
    print(f"Scam messages missed:           {fn} of {n1}")


if __name__ == "__main__":
    main()