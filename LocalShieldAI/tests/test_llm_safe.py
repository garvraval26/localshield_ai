"""A likely_safe result must never be explained as 'not safe'; allowlisted links skip Llama."""
import json

import pytest

from llm.validator import LlamaResponseError, fallback_response, validate_response
from services.analysis_service import AnalysisService


def _reply(expl, advice=None):
    return json.dumps({"explanation": expl,
                       "advice": advice or ["Type the official address yourself.",
                                            "Never share OTPs or passwords.",
                                            "Do not trust a link just because it looks familiar."]})


@pytest.mark.parametrize("text", [
    "The URL is not considered safe.",
    "This link may not be safe to use.",
    "This website is unsafe.",
    "The domain isn't safe because it is unfamiliar.",
    "This site is dangerous.",
    "It is not trustworthy.",
    "This looks like a scam.",
])
def test_likely_safe_result_cannot_be_called_not_safe(text):
    with pytest.raises(LlamaResponseError):
        validate_response(_reply(text), "likely_safe")


@pytest.mark.parametrize("text", [
    "No strong warning signs were found. This does not prove the link is safe.",
    "The detector found few warning signs, but this is not a guarantee of safety.",
    "Low risk does not mean the link cannot be harmful, so stay careful.",
    "This is not a scam indicator on its own, but check the sender.",
    "A low score should not be treated as proof that it is safe.",
])
def test_honest_likely_safe_wording_is_accepted(text):
    out = validate_response(_reply(text), "likely_safe")
    assert out["explanation"]


def test_not_safe_is_fine_for_flagged_results():
    out = validate_response(_reply("This link is not safe because it imitates a bank."), "high_risk")
    assert out["explanation"]


def test_fallback_text_passes_the_validator():
    for level in ("likely_safe", "suspicious", "high_risk"):
        fb = fallback_response({"type": "url", "risk_level": level, "score": 0.1,
                                "warning_signs": []})
        validate_response(json.dumps(fb), level)


class _Llama:
    called = False

    def explain(self, detection, original):
        _Llama.called = True
        return {"source": "llama", "model": "x", "error": None, "explanation": "not considered safe",
                "advice": ["a"]}

    def status(self):
        return {}


class _Detector:
    def analyze(self, text):
        return {"type": "url", "score": 0.0, "model_score": 0.0, "risk_level": "likely_safe",
                "host": "www.google.com", "warning_signs": [], "rule": {"verdict": "safe", "flags": []}}


def test_allowlisted_link_skips_llama():
    _Llama.called = False
    svc = AnalysisService(llama=_Llama())
    svc._detectors["url"] = _Detector()
    out = svc.analyze("https://www.google.com/")
    assert out["ok"] and not _Llama.called
    assert out["explanation"]["source"] == "known_site_list"
    assert "not considered safe" not in out["explanation"]["explanation"]
    assert "www.google.com" in out["explanation"]["explanation"]


def test_other_links_still_use_llama():
    class D(_Detector):
        def analyze(self, text):
            r = super().analyze(text)
            r["rule"] = {"verdict": "review", "flags": []}
            return r
    _Llama.called = False
    svc = AnalysisService(llama=_Llama())
    svc._detectors["url"] = D()
    svc.analyze("https://example.org/")
    assert _Llama.called


@pytest.mark.parametrize("text", [
    "This link is guaranteed safe.",
    "We guarantee that it is safe to use.",
])
def test_guaranteed_safe_is_still_rejected(text):
    with pytest.raises(LlamaResponseError):
        validate_response(_reply(text), "likely_safe")