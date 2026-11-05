"""Train the URL detector. Usage: python -m detector.train_url
Needs data/raw/phishing_urls.txt and data/raw/tranco.csv (scripts/download_url_data.py).
Split by registered domain: 60% train / 20% validation / 20% test."""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from detector.common import make_meta, save_artifacts
from detector.evaluate import evaluate_scores
from detector.thresholds import pick_thresholds
from detector.url_features import (InvalidInputError, feature_vector, host_features,
                                   parse_url, registered_domain, url_warning_signs)

ROOT = Path(__file__).resolve().parent.parent
PHISH = ROOT / "data" / "raw" / "phishing_urls.txt"
LEGIT = ROOT / "data" / "raw" / "tranco.csv"
MODEL_OUT = ROOT / "models" / "url_model.joblib"
LEGIT_PER_PHISH = 3
SEED = 42


def build_frame(phish_urls, legit_hosts) -> pd.DataFrame:
    rows = []
    for label, items in ((1, phish_urls), (0, [f"https://{h}" for h in legit_hosts])):
        for u in items:
            try:
                parts, host = parse_url(u)
            except InvalidInputError:
                continue
            rows.append({"y": label, "url": u, "group": registered_domain(host),
                         **host_features(host, bool(parts.username))})
    df = pd.DataFrame(rows)
    return df.groupby(["group", "y"], sort=False).head(3).reset_index(drop=True)


def miss_analysis(urls, scores, flag_threshold) -> dict:
    """Phishing URLs the model scored below the flag threshold (often hacked sites with
    clean-looking hostnames) and whether the rule-based signs would still catch them."""
    missed = [u for u, s in zip(urls, scores) if s < flag_threshold]
    with_any = with_path = 0
    for u in missed:
        parts, host = parse_url(u)
        signs = url_warning_signs(parts, host)
        with_any += bool(signs)
        with_path += any("path or query" in s for s in signs)
    return {"phishing_in_test": len(urls), "missed_by_model": len(missed),
            "missed_but_has_rule_sign": with_any, "missed_but_has_path_keyword": with_path,
            "note": "Hostname-only model cannot see hacked legitimate domains."}


def train_from_frame(df: pd.DataFrame, dataset_name="OpenPhish feed + Tranco top-1M"):
    X = np.array([feature_vector(r) for r in df.to_dict("records")])
    y = df["y"].to_numpy()
    groups = df["group"].to_numpy()
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tmp, te = next(outer.split(X, y, groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    tr_i, va_i = next(inner.split(X[tmp], y[tmp], groups[tmp]))
    tr, va = tmp[tr_i], tmp[va_i]
    assert not (set(groups[tr]) & set(groups[te])) and not (set(groups[va]) & set(groups[te]))
    model = make_pipeline(StandardScaler(),
                          LogisticRegression(max_iter=2000, class_weight="balanced"))
    model.fit(X[tr], y[tr])
    th = pick_thresholds(y[va], model.predict_proba(X[va])[:, 1])
    te_scores = model.predict_proba(X[te])[:, 1]
    metrics = evaluate_scores(y[te], te_scores, th["suspicious_at"], th["high_risk_at"],
                              ("legit", "phishing"))
    metrics["train_class_balance"] = {"legit": int((y[tr] == 0).sum()), "phishing": int((y[tr] == 1).sum())}
    is_p = y[te] == 1
    metrics["miss_analysis"] = miss_analysis(df["url"].to_numpy()[te][is_p], te_scores[is_p],
                                             th["suspicious_at"])
    print("Miss analysis:", metrics["miss_analysis"])
    sizes = {"train": len(tr), "validation": len(va), "test": len(te)}
    return model, make_meta("url", dataset_name, sizes, th), metrics


def main() -> None:
    for p in (PHISH, LEGIT):
        if not p.exists():
            raise FileNotFoundError(f"{p} not found. Run: python scripts\\download_url_data.py")
    phish = [l.strip() for l in PHISH.read_text(encoding="utf-8").splitlines() if l.strip()]
    tranco = pd.read_csv(LEGIT, header=None, names=["rank", "domain"])
    n = min(len(tranco), LEGIT_PER_PHISH * len(phish))
    legit = tranco.sample(n=n, random_state=SEED)["domain"].tolist()
    print(f"Phishing URLs: {len(phish)} | Legit domains sampled: {len(legit)}")
    df = build_frame(phish, legit)
    print(f"Usable rows: {len(df)}\n{df['y'].value_counts().rename({0: 'legit', 1: 'phishing'})}")
    model, meta, metrics = train_from_frame(df)
    print(f"Chosen thresholds (from validation): {meta['suspicious_at']} / {meta['high_risk_at']}")
    save_artifacts(model, meta, metrics, MODEL_OUT)
    print(f"Saved model {meta['model_version']} to {MODEL_OUT}")


if __name__ == "__main__":
    main()
