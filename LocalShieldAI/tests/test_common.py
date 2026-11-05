import numpy as np

from detector.common import level_from_score
from detector.evaluate import calibration_report
from detector.thresholds import pick_thresholds


def test_level_from_score():
    assert level_from_score(0.9, 0.4, 0.75) == "high_risk"
    assert level_from_score(0.5, 0.4, 0.75) == "suspicious"
    assert level_from_score(0.1, 0.4, 0.75) == "likely_safe"


def test_thresholds_meet_targets_and_are_ordered():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(300), np.ones(100)].astype(int)
    s = np.r_[rng.beta(2, 8, 300), rng.beta(8, 2, 100)]
    th = pick_thresholds(y, s)
    assert th["suspicious_at"] <= th["high_risk_at"]
    fpr = ((s >= th["suspicious_at"]) & (y == 0)).sum() / 300
    assert fpr <= 0.15 + 1e-9

def test_calibration_perfect_and_bad():
    y = np.array([0, 1] * 50)
    assert calibration_report(y, y.astype(float))["ece"] == 0.0
    assert calibration_report(y, np.full(100, 0.95))["ece"] > 0.3
