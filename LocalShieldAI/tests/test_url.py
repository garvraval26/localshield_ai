import tempfile
from pathlib import Path

import pytest

from detector.common import save_artifacts
from detector.errors import ModelMissingError
from detector.train_url import build_frame, train_from_frame
from detector.url_detector import UrlDetector
from detector.url_features import (InvalidInputError, parse_url, registered_domain,
                                   url_warning_signs)


def _detector(tmp):
    phish = [f"http://secure-login-{i}.verify-account{i}.xyz/login" for i in range(80)]
    df = build_frame(phish, [f"site{i}.com" for i in range(240)])
    model, meta, metrics = train_from_frame(df, "synthetic")
    path = Path(tmp) / "url_model.joblib"
    save_artifacts(model, meta, metrics, path)
    return UrlDetector(path), meta, metrics


def test_rejects_bad_input():
    for bad in ["", "   ", "javascript:alert(1)", "http://exa mple.com", "ftp://a.com/x", "a" * 3000]:
        with pytest.raises(InvalidInputError):
            parse_url(bad)


def test_scheme_optional_and_host_lowercased():
    assert parse_url("Example.COM/path")[1] == "example.com"


def test_ip_and_userinfo_signs():
    parts, host = parse_url("http://user@192.168.1.5:8080/login")
    signs = " ".join(url_warning_signs(parts, host))
    assert "raw IP" in signs and "'@'" in signs and "port" in signs


def test_registered_domain():
    assert registered_domain("a.b.example.co.in") == "example.co.in"
    assert registered_domain("www.google.com") == "google.com"


def test_missing_model_gives_clear_error():
    with pytest.raises(ModelMissingError):
        UrlDetector(Path("nope.joblib"))


def test_detector_output_version_floor_and_no_network():
    with tempfile.TemporaryDirectory() as tmp:
        det, meta, metrics = _detector(tmp)
        r = det.analyze("http://secure-login-9.verify-account9.xyz/login")
        assert r["model_version"] == meta["model_version"]
        assert r["risk_level"] == "high_risk"
        ip = det.analyze("http://192.168.0.1/login")
        assert ip["risk_level"] != "likely_safe"  # structural floor
        assert "miss_analysis" in metrics and "calibration" in metrics
        with pytest.raises(InvalidInputError):
            det.analyze("javascript:alert(1)")
