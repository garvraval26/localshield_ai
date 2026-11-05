"""The plain-Python scorers (no scikit-learn) must give the same scores as scikit-learn."""
import json
import random

import joblib
import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline, make_union
from sklearn.preprocessing import StandardScaler

from detector.portable import PlainSmsModel, PlainUrlModel, load_model
from detector.sms_detector import SmsDetector
from detector.url_detector import UrlDetector
from detector.url_features import feature_vector, host_features
from scripts.export_portable import export_sms, export_url

SCAM = ["urgent", "verify", "account", "blocked", "kyc", "click", "prize", "free", "win", "claim",
        "bank", "otp", "refund", "limited", "offer", "now", "http://bad-site.xyz/login", "Rs", "5000"]
HAM = ["lunch", "tomorrow", "meeting", "see", "you", "at", "home", "call", "me", "later", "thanks",
       "dinner", "class", "notes", "ok", "bro", "match", "7", "pm", "café", "naïve"]


def _texts(rng, n):
    rows = []
    for i in range(n):
        spam = i % 3 == 0
        pool = (SCAM + HAM[:5]) if spam else (HAM + SCAM[:3])
        words = [rng.choice(pool) for _ in range(rng.randint(3, 14))]
        rows.append((int(spam), " ".join(words)))
    return rows


@pytest.fixture(scope="module")
def sms_pipeline():
    rng = random.Random(1)
    rows = _texts(rng, 900)
    X, y = [t for _, t in rows], [l for l, _ in rows]
    model = make_pipeline(
        make_union(TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True),
                   TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                   sublinear_tf=True)),
        LogisticRegression(max_iter=1000, class_weight="balanced"))
    model.fit(X, y)
    return model


@pytest.fixture(scope="module")
def url_pipeline():
    rng = np.random.default_rng(2)
    hosts_good = [f"{w}.com" for w in ("google", "amazon", "wikipedia", "github", "python", "bbc")] * 20
    hosts_bad = [f"{rng.choice(['paytm','sbi','hdfc'])}-{rng.choice(['kyc','login','verify'])}-"
                 f"update{int(rng.integers(0, 999))}.{rng.choice(['xyz','top','click'])}" for _ in range(60)]
    hosts_bad += ["192.168.1.5", "10.0.0.7", "a.b.c.d.evil.icu"] * 5
    X = np.array([feature_vector(host_features(h)) for h in hosts_good + hosts_bad])
    y = np.array([0] * len(hosts_good) + [1] * len(hosts_bad))
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
    model.fit(X, y)
    return model


def test_sms_scores_match_sklearn(sms_pipeline):
    plain = PlainSmsModel(json.loads(json.dumps(export_sms(sms_pipeline))))
    rng = random.Random(7)
    odd = ["", "   ", "a", "I", "OK!!", "Ünïcödé  téxt\twith\n\nspaces", "😀😀 free prize 😀",
           "x" * 900, "URGENT!!! Verify KYC NOW at http://sbi-kyc.xyz/login", "12345 67890",
           "café naïve", "A  B   C", "don't can't won't", "under_score and-hyphen", "你好 世界 free"]
    texts = odd + [t for _, t in _texts(rng, 400)]
    want = sms_pipeline.predict_proba(texts)[:, 1]
    got = np.array([p[1] for p in plain.predict_proba(texts)])
    assert np.max(np.abs(want - got)) < 1e-9


def test_url_scores_match_sklearn(url_pipeline):
    plain = PlainUrlModel(json.loads(json.dumps(export_url(url_pipeline))))
    hosts = ["google.com", "paytm-kyc-update.xyz", "192.168.1.5", "xn--80ak6aa92e.com", "a.b.c.d.e.f.evil.top",
             "x.co", "gooogle.cooom", "login-secure-bank-verify.click", "localhost.local"]
    X = [feature_vector(host_features(h)) for h in hosts]
    want = url_pipeline.predict_proba(np.array(X))[:, 1]
    got = np.array([p[1] for p in plain.predict_proba(X)])
    assert np.max(np.abs(want - got)) < 1e-9


def test_detectors_give_same_answer_with_json_models(tmp_path, sms_pipeline, url_pipeline):
    meta = {"model_version": "test", "suspicious_at": 0.3, "high_risk_at": 0.7}
    for name, pipe, fn in (("sms", sms_pipeline, export_sms), ("url", url_pipeline, export_url)):
        joblib.dump(pipe, tmp_path / f"{name}_model.joblib")
        (tmp_path / f"{name}_model.json").write_text(json.dumps(fn(pipe)))
        (tmp_path / f"{name}_meta.json").write_text(json.dumps(meta))
    a = SmsDetector(tmp_path / "sms_model.joblib")
    b = SmsDetector(tmp_path / "sms_model.json")
    assert isinstance(b.model, PlainSmsModel)
    for text in ["URGENT! Verify KYC now at http://sbi-kyc.xyz/login", "see you at lunch tomorrow"]:
        ra, rb = a.analyze(text), b.analyze(text)
        assert ra["risk_level"] == rb["risk_level"]
        assert abs(ra["score"] - rb["score"]) < 1e-3
    c = UrlDetector(tmp_path / "url_model.joblib")
    d = UrlDetector(tmp_path / "url_model.json")
    assert isinstance(d.model, PlainUrlModel)
    for u in ["http://paytm-kyc-update.xyz/login", "https://www.google.com/", "http://192.168.1.5/login"]:
        rc, rd = c.analyze(u), d.analyze(u)
        assert rc["risk_level"] == rd["risk_level"]
        assert abs(rc["score"] - rd["score"]) < 1e-3


def test_bad_json_kind_is_refused(tmp_path):
    p = tmp_path / "x_model.json"
    p.write_text(json.dumps({"kind": "nope"}))
    with pytest.raises(ValueError):
        load_model(p)


def test_portable_module_does_not_need_sklearn():
    import ast
    import pathlib
    for f in ("detector/portable.py", "detector/common.py", "detector/sms_detector.py",
              "detector/url_detector.py", "detector/features.py", "detector/sms_links.py",
              "detector/lookalike.py", "detector/known_sites.py", "detector/url_features.py"):
        tree = ast.parse(pathlib.Path(f).read_text())
        top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        names = {a.name.split(".")[0] for n in top for a in n.names} | \
                {n.module.split(".")[0] for n in top if isinstance(n, ast.ImportFrom) and n.module}
        assert not names & {"sklearn", "numpy", "pandas", "joblib", "scipy"}, (f, names)