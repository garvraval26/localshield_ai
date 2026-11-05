"""Evaluate the trained SMS model on a SEPARATE hand-written set of modern Indian-style
scam/legit messages that was never used for training or threshold tuning.
Usage: python -m detector.eval_external"""
import csv
from pathlib import Path

from detector.evaluate import binary_metrics
from detector.sms_detector import SmsDetector

CSV = Path(__file__).resolve().parent.parent / "data" / "eval" / "indian_sms_eval.csv"


def main(detector=None, path: Path = CSV) -> dict:
    det = detector or SmsDetector()
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    y = [int(r["label"]) for r in rows]
    res = [det.analyze(r["text"]) for r in rows]
    pred = [int(x["risk_level"] != "likely_safe") for x in res]  # flagged = suspicious or high
    m = binary_metrics(y, pred)
    print(f"External set: {len(rows)} messages (scam={sum(y)}, legit={len(y)-sum(y)})")
    print(f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} {m['confusion_matrix']}")
    print("\nMissed scams (model said likely_safe):")
    for r, x, p in zip(rows, res, pred):
        if r["label"] == "1" and not p:
            print(f"  [{x['score']}] {r['text']}")
    print("\nFalse alarms on legitimate messages:")
    for r, x, p in zip(rows, res, pred):
        if r["label"] == "0" and p:
            print(f"  [{x['score']}] {r['text']}")
    return m


if __name__ == "__main__":
    main()
