import tempfile
from pathlib import Path

import pandas as pd

from detector.common import save_artifacts
from detector.sms_detector import SmsDetector
from detector.sms_links import brands_mentioned, check_sms_links, extract_links
from detector.train import train_sms

HAM = ["see you at lunch tomorrow {}", "please send the notes for class {}", "call me when free {}"]
SCAM = ["You won a prize claim reward {} free", "free entry win cash txt now {}"]


def test_extract_links_strips_punctuation():
    assert extract_links("go to http://a.xyz/x, or www.b.top.") == ["http://a.xyz/x", "www.b.top"]


def test_brand_mismatch_and_lookalike_raise():
    r = check_sms_links("HDFC Bank: verify your account at http://hdfc-kyc-update.xyz/login")
    assert r["raise"] and r["links"][0]["status"] in ("brand_mismatch", "lookalike")
    r = check_sms_links("Dear customer click http://gooogle.cooom/x")
    assert r["raise"] and r["links"][0]["status"] == "lookalike"


def test_genuine_links_do_not_raise():
    for t in ["HDFC Bank: view your statement at https://www.hdfcbank.com",
              "Your Amazon order: https://www.amazon.in/orders",
              "SBI: details at https://www.sbi.co.in/web/personal-banking",
              "Reminder: lecture notes at https://www.wikipedia.org"]:
        assert not check_sms_links(t)["raise"], t


def test_shortener_is_noted_but_alone_does_not_raise():
    r = check_sms_links("Your parcel: http://bit.ly/abc123")
    assert any("shortener" in s for s in r["signs"]) and not r["raise"]


def test_brand_without_links_is_ignored():
    assert check_sms_links("Your HDFC Bank OTP is 123456. Do not share it.")["links"] == []
    assert "hdfc" in brands_mentioned("Your HDFC Bank OTP")


def test_detector_raises_but_never_lowers():
    rows = [(1, SCAM[i % 2].format(i)) for i in range(120)] + \
           [(0, HAM[i % 3].format(i)) for i in range(240)]
    with tempfile.TemporaryDirectory() as tmp:
        model, meta, metrics = train_sms(pd.DataFrame(rows, columns=["y", "text"]), "toy")
        path = Path(tmp) / "sms_model.joblib"
        save_artifacts(model, meta, metrics, path)
        det = SmsDetector(path)
        r = det.analyze("call me when free 7. HDFC Bank verify your account http://hdfc-kyc.xyz/a")
        assert r["risk_level"] != "likely_safe" and r["model_score"] <= r["score"]
        assert any("HDFC" in s or "hdfc" in s for s in r["warning_signs"])
        good = det.analyze("call me when free 9. HDFC Bank statement https://www.hdfcbank.com")
        assert good["risk_level"] == "likely_safe"
        assert good["links"][0]["status"] == "known_site"