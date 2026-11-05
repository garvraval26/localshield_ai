"""Choose risk thresholds from VALIDATION data (never from the test set)."""
import numpy as np


def pick_thresholds(y_val, scores, recall_target=0.95, precision_target=0.95,
                    max_fpr=0.15) -> dict:
    """suspicious_at: catch >= recall_target of scams BUT never flag more than
    max_fpr of legitimate items (if both cannot hold, the false-alarm cap wins).
    high_risk_at: lowest cutoff where flagged items are >= precision_target scams."""
    y = np.asarray(y_val)
    s = np.asarray(scores, dtype=float)
    cands = np.unique(s)
    n_pos = max(int((y == 1).sum()), 1)
    n_neg = max(int((y == 0).sum()), 1)

    t_recall = float(cands.min())
    for t in cands[::-1]:
        if ((s >= t) & (y == 1)).sum() / n_pos >= recall_target:
            t_recall = float(t)
            break

    t_fpr = float(cands.max())
    for t in cands:
        if ((s >= t) & (y == 0)).sum() / n_neg <= max_fpr:
            t_fpr = float(t)
            break
    susp = max(t_recall, t_fpr)

    high = 0.90
    for t in cands:
        flagged = s >= t
        if flagged.sum() and ((flagged & (y == 1)).sum() / flagged.sum()) >= precision_target:
            high = float(t)
            break
    high = max(high, susp)
    return {"suspicious_at": round(susp, 4), "high_risk_at": round(high, 4),
            "recall_target": recall_target, "precision_target": precision_target,
            "max_fpr": max_fpr}