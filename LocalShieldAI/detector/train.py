"""Train the SMS detector. Usage: python -m detector.train
Split: 60% train / 20% validation (threshold tuning) / 20% test (reporting only).

Optional extra TRAINING data: data/train_extra/transactional_sms.csv (label,text),
made by scripts/make_transactional_data.py. It is added to the TRAIN part only, so
validation and test stay pure UCI data, and any text that also appears in data/eval/
is removed so the evaluation files remain untouched."""
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline, make_union

from detector.common import make_meta, save_artifacts
from detector.evaluate import evaluate_scores
from detector.thresholds import pick_thresholds

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "raw" / "SMSSpamCollection"
EXTRA = ROOT / "data" / "train_extra" / "transactional_sms.csv"
EVAL_DIR = ROOT / "data" / "eval"
MODEL_OUT = ROOT / "models" / "sms_model.joblib"
SEED = 42


def load_sms(path: Path = DATA) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run: python scripts\\download_data.py")
    df = pd.read_csv(path, sep="\t", header=None, names=["label", "text"], encoding="latin-1")
    df["y"] = (df["label"] == "spam").astype(int)
    return df


def _norm(t) -> str:
    return " ".join(str(t).lower().split())


def load_extra(path: Path = EXTRA, eval_dir: Path = EVAL_DIR):
    """Extra training rows (columns y, text), or None. Rows that also appear in
    data/eval/*.csv are dropped, so evaluation data never leaks into training."""
    if not path.exists():
        return None
    ex = pd.read_csv(path)
    ex["y"] = ex["label"].astype(int)
    held_out = set()
    if eval_dir.exists():
        for f in eval_dir.glob("*.csv"):
            try:
                t = pd.read_csv(f, on_bad_lines="skip")
            except Exception:
                continue
            for col in t.columns:
                if str(col).lower() in ("text", "message", "sms", "v2"):
                    held_out |= {_norm(x) for x in t[col].dropna()}
    ex = ex[~ex["text"].map(_norm).isin(held_out)]
    return ex[["y", "text"]].drop_duplicates(subset="text").reset_index(drop=True)


def train_sms(df: pd.DataFrame, dataset_name="UCI SMS Spam Collection", extra=None):
    # Leakage guard: drop exact duplicate texts BEFORE splitting.
    df = df.drop_duplicates(subset="text").reset_index(drop=True)
    X_tmp, X_te, y_tmp, y_te = train_test_split(
        df["text"], df["y"], test_size=0.2, stratify=df["y"], random_state=SEED)
    X_tr, X_va, y_tr, y_va = train_test_split(
        X_tmp, y_tmp, test_size=0.25, stratify=y_tmp, random_state=SEED)
    n_extra = 0
    if extra is not None and len(extra):
        seen = set(df["text"].map(_norm))
        extra = extra[~extra["text"].map(_norm).isin(seen)]  # never repeat a UCI text
        X_tr = pd.concat([X_tr, extra["text"]], ignore_index=True)
        y_tr = pd.concat([y_tr, extra["y"]], ignore_index=True)
        n_extra = len(extra)
        dataset_name += " + template-generated transactional messages (train only)"
    model = make_pipeline(
        make_union(TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True),
                   TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                   sublinear_tf=True)),
        LogisticRegression(max_iter=1000, class_weight="balanced"))
    model.fit(X_tr, y_tr)  # vectorizers are fitted on TRAIN only
    th = pick_thresholds(y_va.to_numpy(), model.predict_proba(X_va)[:, 1])
    metrics = evaluate_scores(y_te.to_numpy(), model.predict_proba(X_te)[:, 1],
                              th["suspicious_at"], th["high_risk_at"], ("ham", "spam"))
    metrics["train_class_balance"] = {"ham": int((y_tr == 0).sum()), "spam": int((y_tr == 1).sum())}
    sizes = {"train": len(X_tr), "train_extra": n_extra, "validation": len(X_va), "test": len(X_te)}
    return model, make_meta("sms", dataset_name, sizes, th), metrics


def main() -> None:
    df = load_sms()
    print(f"Loaded {len(df)} rows; class balance:\n{df['label'].value_counts()}")
    extra = load_extra()
    print("Extra training data:", "none (data/train_extra/transactional_sms.csv not found)"
          if extra is None else f"{len(extra)} rows ({int((extra['y'] == 0).sum())} normal, "
                                f"{int((extra['y'] == 1).sum())} scam)")
    model, meta, metrics = train_sms(df, extra=extra)
    print(f"Chosen thresholds (from validation): {meta['suspicious_at']} / {meta['high_risk_at']}")
    save_artifacts(model, meta, metrics, MODEL_OUT)
    print(f"Saved model {meta['model_version']} to {MODEL_OUT}")


if __name__ == "__main__":
    main()