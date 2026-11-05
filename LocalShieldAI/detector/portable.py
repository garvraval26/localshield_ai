"""Plain-Python scorers that reproduce the trained scikit-learn models WITHOUT scikit-learn.

Why: the Android app (Chaquopy) cannot install scikit-learn for Python 3.13. Both of our
models are small linear models, so a model is just numbers (vocabulary, IDF weights,
coefficients, scaler values). scripts/export_portable.py writes them to JSON and this
module scores with them. tests/test_portable.py proves the scores match scikit-learn.

The code follows scikit-learn's own TfidfVectorizer / StandardScaler / LogisticRegression
logic (word 1-2 grams, char_wb 3-5 grams, sublinear tf, L2 norm per vectorizer, FeatureUnion
order). If the training settings in detector/train.py change, update this file too."""
import json
import math
import re
from pathlib import Path

_TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")
_WHITE_RE = re.compile(r"\s\s+")


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _word_terms(text: str, ngram_range):
    tokens = _TOKEN_RE.findall(text.lower())
    min_n, max_n = ngram_range
    out = tokens
    if max_n != 1:
        original = tokens
        if min_n == 1:
            out = list(original)
            min_n += 1
        else:
            out = []
        n_tok = len(original)
        for n in range(min_n, min(max_n + 1, n_tok + 1)):
            for i in range(n_tok - n + 1):
                out.append(" ".join(original[i:i + n]))
    return out


def _char_wb_terms(text: str, ngram_range):
    text = _WHITE_RE.sub(" ", text.lower())
    min_n, max_n = ngram_range
    out = []
    for w in text.split():
        w = " " + w + " "
        w_len = len(w)
        for n in range(min_n, max_n + 1):
            offset = 0
            out.append(w[offset:offset + n])
            while offset + n < w_len:
                offset += 1
                out.append(w[offset:offset + n])
            if offset == 0:
                break
    return out


class PlainSmsModel:
    """TF-IDF (word + char_wb) + logistic regression, from exported numbers."""

    def __init__(self, data: dict):
        self.parts = data["vectorizers"]      # each: analyzer, ngram_range, terms {term: [idf, coef]}
        self.intercept = float(data["intercept"])

    def score(self, text: str) -> float:
        z = self.intercept
        for part in self.parts:
            if part["analyzer"] == "word":
                terms = _word_terms(text, part["ngram_range"])
            else:
                terms = _char_wb_terms(text, part["ngram_range"])
            table = part["terms"]
            counts = {}
            for t in terms:
                if t in table:
                    counts[t] = counts.get(t, 0) + 1
            if not counts:
                continue
            total = 0.0
            sq = 0.0
            for t, c in counts.items():
                idf, coef = table[t]
                w = (1.0 + math.log(c)) * idf
                total += w * coef
                sq += w * w
            if sq > 0.0:
                z += total / math.sqrt(sq)
        return _sigmoid(z)

    def predict_proba(self, texts):
        out = []
        for t in texts:
            p = self.score(t)
            out.append([1.0 - p, p])
        return out


class PlainUrlModel:
    """StandardScaler + logistic regression on the 11 host features."""

    def __init__(self, data: dict):
        self.mean = data["mean"]
        self.scale = data["scale"]
        self.coef = data["coef"]
        self.intercept = float(data["intercept"])

    def score(self, vector) -> float:
        z = self.intercept
        for x, m, s, c in zip(vector, self.mean, self.scale, self.coef):
            z += c * ((x - m) / s)
        return _sigmoid(z)

    def predict_proba(self, rows):
        out = []
        for r in rows:
            p = self.score(r)
            out.append([1.0 - p, p])
        return out


def load_model(path):
    """Load a model: .joblib (scikit-learn, laptop) or .json (portable, phone)."""
    path = Path(path)
    if path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        kind = data.get("kind")
        if kind == "sms":
            return PlainSmsModel(data)
        if kind == "url":
            return PlainUrlModel(data)
        raise ValueError(f"Unknown portable model kind in {path}: {kind!r}")
    import joblib  # laptop only
    return joblib.load(path)