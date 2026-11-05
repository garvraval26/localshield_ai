from pathlib import Path

from detector.common import level_from_score, load_meta, meta_path_for
from detector.domain_allowlist import check_url
from detector.errors import ModelMissingError
from detector.lookalike import find_lookalike
from detector.portable import load_model
from detector.url_features import (feature_vector, host_features, parse_url,
                                   url_warning_signs)

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_model.joblib"

# Provisional thresholds on RAW model scores (NOT calibrated probabilities).
SUSPICIOUS_AT = 0.40
HIGH_RISK_AT = 0.75
# Structural red flags that force at least "suspicious" regardless of the model.
FLOOR_FEATURES = ("is_ip", "has_userinfo", "has_punycode")
# Score shown when a hard domain rule fires (e.g. invalid TLD, typosquat).
RULE_MALICIOUS_SCORE = 0.95


class UrlDetector:
    def __init__(self, path: Path = MODEL_PATH):
        if not path.exists():
            raise ModelMissingError(
                f"URL model not found at {path}. Run: python -m detector.train_url")
        self.model = load_model(path)
        self.meta = {"suspicious_at": SUSPICIOUS_AT, "high_risk_at": HIGH_RISK_AT,
                     **load_meta(meta_path_for(path))}

    def analyze(self, raw_url: str) -> dict:
        parts, host = parse_url(raw_url)  # raises InvalidInputError
        feats = host_features(host, bool(parts.username))

        # level names taken from your own level_from_score, so nothing is hard-coded
        safe_level = level_from_score(0.0, self.meta["suspicious_at"], self.meta["high_risk_at"])
        top_level = level_from_score(1.0, self.meta["suspicious_at"], self.meta["high_risk_at"])

        # ---- Allowlist / domain rules (see detector/domain_allowlist.py) ----
        rule = check_url(raw_url)

        # 1) Exact allowlisted domain (or trusted suffix like .gov.in): skip the model.
        if rule["verdict"] == "safe" and not feats["has_userinfo"]:
            return {"type": "url", "score": 0.0, "model_score": 0.0,
                    "risk_level": safe_level, "rule_floor_applied": False,
                    "lookalike": None, "model_version": self.meta["model_version"],
                    "host": host, "features": feats, "warning_signs": [],
                    "rule": rule}

        # ---- Everything else goes through the model as before ----
        score = float(self.model.predict_proba([feature_vector(feats)])[0][1])
        level = level_from_score(score, self.meta["suspicious_at"], self.meta["high_risk_at"])
        model_score = score
        signs = url_warning_signs(parts, host)
        floored = False
        if level == safe_level and any(feats[f] for f in FLOOR_FEATURES):
            level, floored = "suspicious", True
        # Rule layer: the model cannot see misspellings of famous names.
        lookalike = find_lookalike(host)
        if lookalike:
            signs.insert(0, lookalike["sign"])
            if level == safe_level:
                level, floored = "suspicious", True
        if floored:
            # keep the shown score consistent with the level; raw score stays available
            score = max(score, self.meta["suspicious_at"])

        # 2) Hard rule hit: invalid TLD, typosquat, brand in subdomain, fake .gov.in ...
        if rule["verdict"] == "malicious":
            signs.insert(0, f"Domain check: {rule['reason']}")
            level, floored = top_level, True
            score = max(score, RULE_MALICIOUS_SCORE)

        # 3) Famous brand name inside a longer domain (paypal-login.com)
        elif any(f.startswith("contains_brand_") for f in rule["flags"]):
            brand = next(f for f in rule["flags"] if f.startswith("contains_brand_"))
            signs.insert(0, f"Domain contains the well-known name '{brand[len('contains_brand_'):]}' "
                            "but is not the official site")
            if level == safe_level:
                level, floored = "suspicious", True
                score = max(score, self.meta["suspicious_at"])

        # 4) Allowlisted site that lets anyone host content (docs.google.com, sites.google.com)
        if "user_content_host" in rule["flags"]:
            signs.append("This is a shared hosting page: anyone can publish content here, "
                         "even on a trusted site")

        return {"type": "url", "score": round(score, 3), "model_score": round(model_score, 3),
                "risk_level": level, "rule_floor_applied": floored,
                "lookalike": lookalike, "model_version": self.meta["model_version"], "host": host,
                "features": feats, "warning_signs": signs, "rule": rule}