import numpy as np
from sklearn.metrics import (brier_score_loss, confusion_matrix, f1_score,
                             precision_score, recall_score)


def binary_metrics(y, pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def calibration_report(y, scores, bins=10) -> dict:
    """Expected calibration error + reliability table. A low ECE on one test set
    does not make scores trustworthy probabilities; we still call them estimates."""
    y = np.asarray(y)
    s = np.asarray(scores, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(s, edges) - 1, 0, bins - 1)
    ece, table = 0.0, []
    for b in range(bins):
        m = idx == b
        if m.sum() == 0:
            continue
        conf, acc = float(s[m].mean()), float(y[m].mean())
        ece += m.sum() / len(s) * abs(conf - acc)
        table.append({"bin": f"{edges[b]:.1f}-{edges[b+1]:.1f}", "n": int(m.sum()),
                      "mean_score": round(conf, 3), "actual_scam_rate": round(acc, 3)})
    return {"ece": round(float(ece), 4), "brier": round(float(brier_score_loss(y, s)), 4),
            "reliability": table}


def evaluate_scores(y, scores, suspicious_at, high_risk_at, labels=("ham", "spam")) -> dict:
    y = np.asarray(y)
    s = np.asarray(scores, dtype=float)
    out = {"at_0.5": binary_metrics(y, (s >= 0.5).astype(int)),
           "at_flag_threshold": {"threshold": suspicious_at,
                                 **binary_metrics(y, (s >= suspicious_at).astype(int))},
           "at_high_risk_threshold": {"threshold": high_risk_at,
                                      **binary_metrics(y, (s >= high_risk_at).astype(int))},
           "test_size": int(len(y)),
           "test_class_balance": {labels[0]: int((y == 0).sum()), labels[1]: int((y == 1).sum())},
           "calibration": calibration_report(y, s)}
    for k in ("at_0.5", "at_flag_threshold", "at_high_risk_threshold"):
        m = out[k]
        cm = m["confusion_matrix"]
        print(f"[{k}] P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
              f"TN={cm['tn']} FP={cm['fp']} FN={cm['fn']} TP={cm['tp']}")
    print(f"Test class balance: {out['test_class_balance']}")
    print(f"Calibration: ECE={out['calibration']['ece']} Brier={out['calibration']['brier']} "
          "(scores remain ESTIMATES, not probabilities)")
    return out
