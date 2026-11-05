"""Helpers shared by the URL and SMS detectors."""
import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_THRESHOLDS = {"suspicious_at": 0.40, "high_risk_at": 0.75}


def level_from_score(score: float, suspicious_at: float, high_risk_at: float) -> str:
    """Map a raw model score to a label. Scores are NOT calibrated probabilities."""
    if score >= high_risk_at:
        return "high_risk"
    if score >= suspicious_at:
        return "suspicious"
    return "likely_safe"


def meta_path_for(model_path: Path) -> Path:
    return model_path.with_name(model_path.stem.replace("_model", "_meta") + ".json")


def load_meta(path: Path) -> dict:
    """Small JSON describing a trained model: version, dataset, thresholds."""
    if not path.exists():
        return {"model_version": "unknown", **DEFAULT_THRESHOLDS}
    return json.loads(path.read_text(encoding="utf-8"))


def make_meta(name: str, dataset: str, sizes: dict, thresholds: dict) -> dict:
    import sklearn  # imported here so the phone app (no scikit-learn) can import this module
    now = datetime.now(timezone.utc)
    return {"model_version": f"{name}-{now:%Y%m%d}", "trained_at": now.isoformat(timespec="seconds"),
            "dataset": dataset, "split_sizes": sizes, "sklearn_version": sklearn.__version__,
            **thresholds}


def save_artifacts(model, meta, metrics, model_path: Path) -> None:
    import joblib
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    meta_path_for(model_path).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    model_path.with_name(model_path.stem.replace("_model", "_metrics") + ".json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8")