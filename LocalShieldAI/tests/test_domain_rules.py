import pytest

from detector.domain_allowlist import check_url, ALLOWLIST
from detector.errors import ModelMissingError
from detector.url_detector import UrlDetector


# ---- rule layer ----
@pytest.mark.parametrize("url", [
    "google.com", "https://mail.google.com", "hdfcbank.com", "onlinesbi.sbi",
    "https://www.amazon.in/deals", "incometax.gov.in", "binance.com",
])
def test_known_safe(url):
    assert check_url(url)["verdict"] == "safe"


@pytest.mark.parametrize("url", [
    "goggle.innn", "goggle.in", "paypa1.com", "amaz0n.in", "binnance.com",
    "google.com.evil.com", "uidai.gov.in.fake.com", "hdfcbank.cmo",
])
def test_known_bad(url):
    assert check_url(url)["verdict"] == "malicious"


def test_user_content_hosts_not_auto_safe():
    assert check_url("https://docs.google.com/forms/x")["verdict"] == "review"
    assert check_url("https://sites.google.com/view/x")["verdict"] == "review"


def test_unknown_domain_goes_to_model():
    assert check_url("https://some-random-shop-xyz.org")["verdict"] == "review"


def test_ip_goes_to_model():
    assert check_url("http://192.168.1.5/login")["verdict"] == "review"


def test_list_size():
    assert len(ALLOWLIST) > 1400


# ---- full detector (needs your trained model) ----
@pytest.fixture(scope="module")
def det():
    try:
        return UrlDetector()
    except ModelMissingError:
        pytest.skip("URL model not trained")


def test_detector_google_safe(det):
    assert det.analyze("https://google.com")["risk_level"] == "likely_safe"


@pytest.mark.parametrize("url", ["https://goggle.in", "https://paypa1.com",
                                 "https://google.com.evil.com"])
def test_detector_flags_lookalikes(det, url):
    r = det.analyze(url)
    assert r["risk_level"] != "likely_safe"
    assert r["warning_signs"]