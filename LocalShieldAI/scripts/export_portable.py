"""Export the trained scikit-learn models to portable JSON (for the Android app).

    python -m scripts.export_portable

Reads  models/sms_model.joblib and models/url_model.joblib
Writes models/sms_model.json   and models/url_model.json
(the *_meta.json threshold files are already JSON and are copied to the app as they are).
Run scripts.check_portable afterwards to prove the scores match."""
import json
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"


def export_sms(pipeline) -> dict:
    union, lr = pipeline.steps[0][1], pipeline.steps[-1][1]
    coef = lr.coef_[0]
    parts, offset = [], 0
    for _, vec in union.transformer_list:
        if vec.sublinear_tf is not True or vec.norm != "l2" or not vec.use_idf or not vec.smooth_idf:
            raise ValueError("Unexpected TF-IDF settings; update detector/portable.py first.")
        analyzer = {"word": "word", "char_wb": "char_wb"}[vec.analyzer]
        terms = {}
        for term, idx in vec.vocabulary_.items():
            terms[term] = [float(vec.idf_[idx]), float(coef[offset + idx])]
        parts.append({"analyzer": analyzer, "ngram_range": list(vec.ngram_range), "terms": terms})
        offset += len(vec.vocabulary_)
    if offset != len(coef):
        raise ValueError("Coefficient count does not match the vocabularies.")
    return {"kind": "sms", "intercept": float(lr.intercept_[0]), "vectorizers": parts}


def export_url(pipeline) -> dict:
    scaler, lr = pipeline.steps[0][1], pipeline.steps[-1][1]
    return {"kind": "url", "mean": [float(x) for x in scaler.mean_],
            "scale": [float(x) for x in scaler.scale_],
            "coef": [float(x) for x in lr.coef_[0]], "intercept": float(lr.intercept_[0])}


def main() -> None:
    for name, fn in (("sms", export_sms), ("url", export_url)):
        src = MODELS / f"{name}_model.joblib"
        out = MODELS / f"{name}_model.json"
        data = fn(joblib.load(src))
        out.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        print(f"{name}: wrote {out} ({out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()