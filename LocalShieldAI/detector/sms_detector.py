from pathlib import Path

from detector.common import level_from_score, load_meta, meta_path_for
from detector.errors import ModelMissingError
from detector.features import sms_warning_signs
from detector.known_sites import load_known
from detector.portable import load_model
from detector.sms_links import check_sms_links

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "sms_model.joblib"
MAX_LEN = 1000
DEFAULTS = {"suspicious_at": 0.30, "high_risk_at": 0.70}


class SmsDetector:
    def __init__(self, path: Path = MODEL_PATH):
        if not path.exists():
            raise ModelMissingError(f"SMS model not found at {path}. Run: python -m detector.train")
        self.model = load_model(path)
        self.meta = {**DEFAULTS, "model_version": "unknown", **load_meta(meta_path_for(path))}
        self.known = load_known()

    def analyze(self, text: str) -> dict:
        text = (text or "").strip()  # the text is DATA; it is never executed or interpreted
        if not text:
            raise ValueError("Message is empty.")
        if len(text) > MAX_LEN:
            raise ValueError(f"Message is too long (max {MAX_LEN} characters).")
        score = float(self.model.predict_proba([text])[0][1])
        model_score = score
        level = level_from_score(score, self.meta["suspicious_at"], self.meta["high_risk_at"])
        signs = sms_warning_signs(text)
        # Rule layer on the links inside the message. It can only RAISE the result.
        links = check_sms_links(text, self.known)
        signs += links["signs"]
        if links["raise"] and level == "likely_safe":
            level = "suspicious"
            score = max(score, self.meta["suspicious_at"])
        return {"type": "sms", "score": round(score, 3), "model_score": round(model_score, 3),
                "risk_level": level, "model_version": self.meta["model_version"],
                "links": links["links"], "warning_signs": signs}